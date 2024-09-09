use crate::{
    parse_tls_record_with_header, TlsMessage, TlsRawRecord, TlsRecordHeader, TlsRecordType,
};
use alloc::vec::Vec;
use nom::{
    error::{Error, ErrorKind},
    Err, IResult, Needed,
};

pub const MAX_RECORD_DATA: usize = 10 * 1024 * 1024;

/// Helper tool to defragment and parse TLS records
#[derive(Debug, Default)]
pub struct TlsRecordsParser {
    record_defrag_buffer: Vec<u8>,
    current_record_type: Option<TlsRecordType>,
}

impl TlsRecordsParser {
    /// Reset the parser state (deleting all previous records)
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Returns `true` if defragmentation is in progress
    pub fn defrag_in_progress(&self) -> bool {
        self.current_record_type.is_some()
    }

    /// Attempt to parse all messages from a single record
    ///
    /// Record types `ChangeCipherSpec` and `Alert` cannot be fragmented.
    ///
    /// This function does not defragment data, but guarantees that no data is copied.
    ///
    /// Returns
    ///     - the bytes remaining, and the list of messages. The remaining bytes should be empty.
    ///     - `Incomplete` if a message is fragmented. Caller should use function [Self::parse_record] instead
    ///     - `ErrorKind::NonEmpty` if defragmentation is already in progress
    pub fn parse_record_nocopy<'a>(
        &mut self,
        record: TlsRawRecord<'a>,
    ) -> IResult<&'a [u8], Vec<TlsMessage<'a>>> {
        if self.defrag_in_progress() {
            return Err(Err::Failure(Error::new(&[], ErrorKind::NonEmpty)));
        }
        match parse_tls_record_with_header(record.data, &record.hdr) {
            Err(Err::Error(e)) | Err(Err::Failure(e)) if e.code == ErrorKind::Complete => {
                Err(Err::Incomplete(Needed::Unknown))
            }
            other => other,
        }
    }

    /// Attempt to parse all messages from a record (iterative)
    ///
    /// Parse all messages from a record, keeping previous fragments (incrementally) if required.
    /// If current record is fragmented, copy record data and return `Incomplete`.
    ///
    /// Record types `ChangeCipherSpec` and `Alert` cannot be fragmented.
    ///
    /// Record types cannot be interleaved. If defragmentation has started for a record type, other record types
    /// will be rejected.
    ///
    /// Returns
    ///     - the bytes remaining, and the list of messages. The remaining bytes should be empty.
    ///     - `Incomplete` if a message is fragmented. Caller should get next record and call function again
    ///     - `ErrorKind::TooLarge` if record contents exceeds [`MAX_RECORD_DATA`]
    ///     - `ErrorKind::Tag` if the provided record does not have the same record type as the first record from the list
    pub fn parse_record<'p, 'a: 'p>(
        &'p mut self,
        record: TlsRawRecord<'a>,
    ) -> IResult<&'p [u8], Vec<TlsMessage<'p>>> {
        if !self.defrag_in_progress() {
            // first fragment

            if record.hdr.record_type == TlsRecordType::Alert
                || record.hdr.record_type == TlsRecordType::ChangeCipherSpec
            {
                return self.parse_record_nocopy(record);
            }

            // before defragmenting, check that message is indeed fragmented
            match parse_tls_record_with_header(record.data, &record.hdr) {
                Ok(res) => return Ok(res),
                Err(Err::Incomplete(_)) => (),
                Err(Err::Error(e)) | Err(Err::Failure(e)) if e.code == ErrorKind::Complete => (),
                Err(e) => return Err(e),
            }

            // record is indeed fragmented: keep contents and return Incomplete
            self.current_record_type = Some(record.hdr.record_type);
            // replace previous buffer
            self.record_defrag_buffer.clear();
            self.record_defrag_buffer.extend_from_slice(record.data);
            return Err(Err::Incomplete(Needed::Unknown));
        }

        // record is not the first
        debug_assert!(!self.record_defrag_buffer.is_empty());

        let record_type = record.hdr.record_type;
        if Some(record_type) != self.current_record_type {
            return Err(Err::Error(Error::new(&[], ErrorKind::Tag)));
        }

        if self
            .record_defrag_buffer
            .len()
            .saturating_add(record.data.len())
            >= MAX_RECORD_DATA
        {
            return Err(Err::Error(Error::new(&[], ErrorKind::TooLarge)));
        }
        self.record_defrag_buffer.extend_from_slice(record.data);

        // create a pseudo-header with correct length
        let header = TlsRecordHeader {
            len: self.record_defrag_buffer.len() as u16,
            ..record.hdr
        };

        match parse_tls_record_with_header(&self.record_defrag_buffer, &header) {
            // we have a complete message list. Remove the parsed records and return
            Ok(r) => {
                // set current_record_type to None, but keep buffer (remaining bytes)
                self.current_record_type = None;
                Ok(r)
            }
            Err(Err::Error(e)) | Err(Err::Failure(e)) if e.code == ErrorKind::Complete => {
                Err(Err::Incomplete(Needed::Unknown))
            }
            // other errors
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{parse_tls_raw_record, TlsMessageHandshake, TlsVersion};

    use super::*;

    static REC_CH: &[u8] = include_bytes!("../assets/client_hello_dhe.bin");
    static REC_CH_FRAG_1: &[u8] = include_bytes!("../assets/tls_record_ch_fragmented_1.bin");
    static REC_CH_FRAG_2: &[u8] = include_bytes!("../assets/tls_record_ch_fragmented_2.bin");

    #[test]
    fn tls_records_parser_nocopy() {
        let (_, record) = parse_tls_raw_record(REC_CH).expect("could not parse client_hello");
        let (_, record1) = parse_tls_raw_record(REC_CH_FRAG_1).expect("could not parse fragment 1");

        //
        // check that _nocopy parser works
        let mut parser = TlsRecordsParser::default();
        let parser_result_nocopy = parser.parse_record_nocopy(record);

        assert!(parser_result_nocopy.is_ok());

        //
        // check that _nocopy parser fails with fragmented data
        let mut parser = TlsRecordsParser::default();
        let parser_result_nocopy = parser.parse_record_nocopy(record1.clone());
        assert!(matches!(parser_result_nocopy, Err(Err::Incomplete(_))));
    }

    #[test]
    fn tls_records_parser_fragmented() {
        let (_, record) = parse_tls_raw_record(REC_CH).expect("could not parse client_hello");
        let (_, record1) = parse_tls_raw_record(REC_CH_FRAG_1).expect("could not parse fragment 1");
        let (_, record2) = parse_tls_raw_record(REC_CH_FRAG_2).expect("could not parse fragment 2");

        //
        // check that parser works with complete data
        let mut parser = TlsRecordsParser::default();
        let (rem, messages) = parser.parse_record(record).expect("parsing failed");
        assert!(rem.is_empty());
        assert_eq!(messages.len(), 1);
        assert!(!parser.defrag_in_progress());

        //
        // check that parser works with fragmented data
        let mut parser = TlsRecordsParser::default();
        let parser_result1 = parser.parse_record(record1);
        assert!(matches!(parser_result1, Err(Err::Incomplete(_))));
        let (rem, messages) = parser
            .parse_record(record2)
            .expect("defragmentation failed");
        assert!(rem.is_empty());
        assert_eq!(messages.len(), 1);
        let ch = &messages[0];
        assert!(matches!(
            ch,
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(_))
        ));

        parser.reset();

        // // does not compile (expected): remaining bytes borrow `parser` and cannot be used
        // // after `parser` has been modified (here, mutably borrowed)
        // assert!(!rem.is_empty());
    }

    #[test]
    fn tls_records_parser_empty() {
        let record = TlsRawRecord {
            hdr: TlsRecordHeader {
                record_type: TlsRecordType::Handshake,
                version: TlsVersion::Tls12,
                len: 0,
            },
            data: &[],
        };
        let mut parser = TlsRecordsParser::default();
        let parser_result = parser.parse_record(record);
        assert!(parser_result.is_err());
    }
}
