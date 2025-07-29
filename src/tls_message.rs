use alloc::{vec, vec::Vec};
use nom::bytes::streaming::take;
use nom::combinator::verify;
use nom::error::{make_error, ErrorKind};
use nom::number::streaming::{be_u16, be_u8};
use nom::{Err, IResult};
use nom_derive::Parse;

use crate::tls_alert::*;
use crate::tls_handshake::*;

/// TLS plaintext message
///
/// Plaintext records can only be found during the handshake.
#[derive(Clone, Debug, PartialEq)]
pub enum TlsMessage<'a> {
    Handshake(TlsMessageHandshake<'a>),
    ChangeCipherSpec,
    Alert(TlsMessageAlert),
    ApplicationData(TlsMessageApplicationData<'a>),
    Heartbeat(TlsMessageHeartbeat<'a>),
}

/// TLS application data
///
/// Since this message can only be sent after the handshake, data is
/// stored as opaque.
#[derive(Clone, Debug, PartialEq)]
pub struct TlsMessageApplicationData<'a> {
    pub blob: &'a [u8],
}

/// TLS heartbeat message, as defined in [RFC6520](https://tools.ietf.org/html/rfc6520)
///
/// Heartbeat messages should not be sent during handshake, but in practise
/// they can (and this caused heartbleed).
#[derive(Clone, Debug, PartialEq)]
pub struct TlsMessageHeartbeat<'a> {
    pub heartbeat_type: TlsHeartbeatMessageType,
    pub payload_len: u16,
    pub payload: &'a [u8],
}

/// Parse a TLS changecipherspec message
// XXX add extra verification hdr.len == 1
pub fn parse_tls_message_changecipherspec(i: &[u8]) -> IResult<&[u8], TlsMessage<'_>> {
    let (i, _) = verify(be_u8, |&tag| tag == 0x01)(i)?;
    Ok((i, TlsMessage::ChangeCipherSpec))
}

/// Parse a TLS alert message
// XXX add extra verification hdr.len == 2
pub fn parse_tls_message_alert(i: &[u8]) -> IResult<&[u8], TlsMessage<'_>> {
    let (i, alert) = TlsMessageAlert::parse(i)?;
    Ok((i, TlsMessage::Alert(alert)))
}

/// Parse a TLS applicationdata message
///
/// Read the entire input as applicationdata
pub fn parse_tls_message_applicationdata(i: &[u8]) -> IResult<&[u8], TlsMessage<'_>> {
    let msg = TlsMessage::ApplicationData(TlsMessageApplicationData { blob: i });
    Ok((&[], msg))
}

/// Parse a TLS heartbeat message
pub fn parse_tls_message_heartbeat(
    i: &[u8],
    tls_plaintext_len: u16,
) -> IResult<&[u8], Vec<TlsMessage<'_>>> {
    let (i, heartbeat_type) = TlsHeartbeatMessageType::parse(i)?;
    let (i, payload_len) = be_u16(i)?;
    if tls_plaintext_len < 3 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, payload) = take(payload_len as usize)(i)?;
    let v = vec![TlsMessage::Heartbeat(TlsMessageHeartbeat {
        heartbeat_type,
        payload_len,
        payload,
    })];
    Ok((i, v))
}
