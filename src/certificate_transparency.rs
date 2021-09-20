///!
///! Certificate Trasparency structures are defined in
///! [RFC6962](https://datatracker.ietf.org/doc/html/rfc6962).
use alloc::vec::Vec;
use core::convert::TryInto;

use nom::{
    bytes::streaming::take,
    combinator::{complete, map_parser},
    multi::{length_data, many0},
    number::streaming::{be_u16, be_u64, be_u8},
    IResult,
};
use nom_derive::*;
use rusticata_macros::newtype_enum;

use crate::{parse_digitally_signed, DigitallySigned};

/// Certificate Transparency Version as defined in [RFC6962 Section 3.2]
/// (https://datatracker.ietf.org/doc/html/rfc6962#section-3.2)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Nom)]
pub struct CtVersion(pub u8);

newtype_enum! {
impl display CtVersion {
    V1 = 0,
}
}

/// LogID as defined in [RFC6962 Section 3.2]
/// (https://datatracker.ietf.org/doc/html/rfc6962#section-3.2)
#[derive(Clone, Debug, PartialEq)]
pub struct CtLogID<'a> {
    pub key_id: &'a [u8; 32],
}

/// CtExtensions as defined in [RFC6962 Section 3.2]
/// (https://datatracker.ietf.org/doc/html/rfc6962#section-3.2)
#[derive(Clone, Debug, PartialEq)]
pub struct CtExtensions<'a>(pub &'a [u8]);

/// Signed Certificate Timestamp as defined in [RFC6962 Section 3.2]
/// (https://datatracker.ietf.org/doc/html/rfc6962#section-3.2)
#[derive(Clone, Debug, PartialEq)]
pub struct SignedCertificateTimestamp<'a> {
    pub version: CtVersion,
    pub id: CtLogID<'a>,
    pub timestamp: u64,
    pub extensions: CtExtensions<'a>,
    pub signature: DigitallySigned<'a>,
}

pub(crate) fn parse_log_id(i: &[u8]) -> IResult<&[u8], CtLogID> {
    let (i, key_id) = take(32usize)(i)?;
    Ok((
        i,
        CtLogID {
            key_id: key_id
                .try_into()
                .expect("take(32) is in sync with key_id size"),
        },
    ))
}

pub(crate) fn parse_ct_extensions(i: &[u8]) -> IResult<&[u8], CtExtensions> {
    let (i, ext_len) = be_u16(i)?;
    let (i, ext_data) = take(ext_len as usize)(i)?;
    Ok((i, CtExtensions(ext_data)))
}

pub(crate) fn parse_ct_signed_certificate_timestamp_content(
    i: &[u8],
) -> IResult<&[u8], SignedCertificateTimestamp> {
    let (i, version) = be_u8(i)?;
    let (i, id) = parse_log_id(i)?;
    let (i, timestamp) = be_u64(i)?;
    let (i, extensions) = parse_ct_extensions(i)?;
    let (i, signature) = parse_digitally_signed(i)?;
    Ok((
        i,
        SignedCertificateTimestamp {
            version: CtVersion(version),
            id,
            timestamp,
            extensions,
            signature,
        },
    ))
}

/// Parses as single Signed Certificate Timestamp entry
pub fn parse_ct_signed_certificate_timestamp(
    i: &[u8],
) -> IResult<&[u8], SignedCertificateTimestamp> {
    map_parser(
        length_data(be_u16),
        parse_ct_signed_certificate_timestamp_content,
    )(i)
}

/// Parses a list of Signed Certificate Timestamp entries
pub fn parse_ct_signed_certificate_timestamp_list(
    i: &[u8],
) -> IResult<&[u8], Vec<SignedCertificateTimestamp>> {
    let (i, sct_len) = be_u16(i)?;
    let (i, sct_list) = map_parser(
        take(sct_len as usize),
        many0(complete(parse_ct_signed_certificate_timestamp)),
    )(i)?;
    Ok((i, sct_list))
}
