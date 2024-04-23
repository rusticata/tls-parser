use core::array;

use nom::error::{make_error, ErrorKind};
use nom::{Err, IResult};

use crate::{
    parse_dtls_message_handshake, DTLSMessage, DTLSMessageHandshake, DTLSMessageHandshakeBody,
};

const MAX_FRAGMENTS: usize = 50;

/// Combine the given fragments into one. Returns true if the fragments made a complete output.
/// The fragments are combined in such a way that the output constitutes a complete DTLSMessage.
///
/// Returns `None` if the fragments are not complete.
///
/// Errors if:
///
/// 1. The output is not big enough to hold the reconstituted messages
/// 2. Fragments are not of the same type (for example ClientHello mixed with Certificate)
/// 3. (Total) length field differs between the fragments
/// 4. Fragment offset/length are not consistent with total length
/// 5. The DTLSMessageHandshakeBody in the message is not a Fragment
/// 6. The message_seq differs between the fragments.
///
/// Panics if there are more than 50 fragments.
pub fn combine_dtls_fragments<'a>(
    fragments: &[DTLSMessageHandshake],
    out: &'a mut [u8],
) -> IResult<&'a [u8], Option<DTLSMessage<'a>>> {
    if fragments.is_empty() {
        return Ok((&[], None));
    }

    if fragments.len() > MAX_FRAGMENTS {
        return Err(Err::Error(make_error(&*out, ErrorKind::TooLarge)));
    }

    const MESSAGE_HEADER_OFFSET: usize = 12;

    // The header all of the fragments share the same DTLSMessage start, apart from the
    // fragment information. This goes into the first 12 bytes.
    if out.len() < MESSAGE_HEADER_OFFSET {
        // Error case 1
        return Err(Err::Error(make_error(&*out, ErrorKind::Fail)));
    }

    // Helper to iterate the fragments in order.
    let ordered = Ordered::new(fragments);

    // Investigate each fragment_offset + fragment_length to figure out
    // the max contiguous range over the fragments.
    let max = ordered.max_contiguous();

    // Unwrap is OK, because we have at least one item (checked above).
    let first_handshake = ordered.iter().next().unwrap();

    if first_handshake.fragment_offset != 0 {
        // The first fragment must start at 0, or we might have
        // missing packets or arriving out of order.
        return Ok((&[], None));
    }

    let msg_type = first_handshake.msg_type;
    let message_seq = first_handshake.message_seq;
    let length = first_handshake.length;

    #[allow(clippy::comparison_chain)]
    if max > length {
        // Error case 4
        return Err(Err::Error(make_error(&*out, ErrorKind::Fail)));
    } else if max < length {
        // We do not have all fragments yet
        return Ok((&[], None));
    }

    // Write the header into output.
    {
        out[0] = msg_type.into(); // The type.
        out[1..4].copy_from_slice(&length.to_be_bytes()[1..]); // 24 bit length
        out[4..6].copy_from_slice(&message_seq.to_be_bytes()); // 16 bit message sequence
        out[6..9].copy_from_slice(&[0, 0, 0]); // 24 bit fragment_offset, which is 0 for the entire message.
        out[9..12].copy_from_slice(&length.to_be_bytes()[1..]); // 24 bit fragment_length, which is entire length.
    }

    let data = &mut out[MESSAGE_HEADER_OFFSET..];

    if data.len() < length as usize {
        // Error case 1
        return Err(Err::Error(make_error(&*out, ErrorKind::Fail)));
    }

    // Loop the fragments, in order and output the data.
    for handshake in ordered.iter() {
        if msg_type != handshake.msg_type {
            // Error case 2
            return Err(Err::Error(make_error(&*out, ErrorKind::Fail)));
        }

        if handshake.length != length {
            // Error case 3
            return Err(Err::Error(make_error(&*out, ErrorKind::Fail)));
        }

        if handshake.message_seq != message_seq {
            // Error case 6
            return Err(Err::Error(make_error(&*out, ErrorKind::Fail)));
        }

        let from = handshake.fragment_offset as usize;
        let to = from + handshake.fragment_length as usize;

        let body = match &handshake.body {
            DTLSMessageHandshakeBody::Fragment(v) => v,
            _ => {
                // Error case 5
                return Err(Err::Error(make_error(&*out, ErrorKind::Fail)));
            }
        };

        // Copy into output.
        data[from..to].copy_from_slice(&body[..]);
    }

    // This parse should succeed now and produce a complete message.
    let (rest, message) = parse_dtls_message_handshake(out)?;

    Ok((rest, Some(message)))
}

struct Ordered<'a, 'b>([usize; MAX_FRAGMENTS], &'a [DTLSMessageHandshake<'b>]);

impl<'a, 'b> Ordered<'a, 'b> {
    fn new(fragments: &'a [DTLSMessageHandshake<'b>]) -> Self {
        // Indexes that will point into handshakes
        let mut order: [usize; MAX_FRAGMENTS] = array::from_fn(|i| i);

        // Sort the index for fragment_offset starts.
        order.sort_by_key(|idx| {
            fragments
                .get(*idx)
                .map(|h| h.fragment_offset)
                // Somewhere outside the fragments length.
                .unwrap_or(*idx as u32 + 1000)
        });

        Self(order, fragments)
    }

    fn iter(&self) -> impl Iterator<Item = &'a DTLSMessageHandshake<'b>> + '_ {
        let len = self.1.len();
        self.0
            .iter()
            .take_while(move |idx| **idx < len)
            .map(move |idx| &self.1[*idx])
    }

    // Find the max contiguous fragment_offset/fragment_length.
    fn max_contiguous(&self) -> u32 {
        let mut max = 0;

        for h in self.iter() {
            // DTLS fragments can overlap, which means the offset might not start at the previous end.
            if h.fragment_offset <= max {
                let start = h.fragment_offset;
                max = start + h.fragment_length;
            } else {
                // Not contiguous.
                return 0;
            }
        }

        max
    }
}

#[cfg(test)]
mod test {
    use crate::parse_dtls_plaintext_record;

    use super::*;

    #[test]
    fn read_dtls_certifiate_fragments() {
        // These are complete packets dumped with wireshark.
        const DTLS_CERT01: &[u8] = include_bytes!("../assets/dtls_cert_frag01.bin");
        const DTLS_CERT02: &[u8] = include_bytes!("../assets/dtls_cert_frag02.bin");
        const DTLS_CERT03: &[u8] = include_bytes!("../assets/dtls_cert_frag03.bin");
        const DTLS_CERT04: &[u8] = include_bytes!("../assets/dtls_cert_frag04.bin");

        let mut fragments = vec![];

        for c in &[DTLS_CERT01, DTLS_CERT02, DTLS_CERT03, DTLS_CERT04] {
            let (_, record) = parse_dtls_plaintext_record(c).expect("parsing failed");

            for message in record.messages {
                // All of these should be fragments.
                assert!(message.is_fragment());

                let handshake = match message {
                    DTLSMessage::Handshake(v) => v,
                    _ => panic!("Expected Handshake"),
                };

                assert!(handshake.is_fragment());
                fragments.push(handshake);
            }
        }

        // Temporary output to combine the fragments into.
        let mut out = vec![0_u8; 4192];
        let (_, message) = combine_dtls_fragments(&fragments, &mut out).expect("combine fragments");

        // This optional should hold Some(DTLSMessage) indicating a complete parse.
        let message = message.expect("Combined fragments");

        println!("{:02x?}", message);
    }
}
