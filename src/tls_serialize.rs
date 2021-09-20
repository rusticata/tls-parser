use crate::tls::*;
use crate::tls_ec::{ECPoint, NamedGroup};
use crate::tls_extensions::{SNIType, TlsExtension, TlsExtensionType};
use alloc::vec::Vec;
use cookie_factory::bytes::{be_u16, be_u24, be_u32, be_u8};
use cookie_factory::combinator::slice;
use cookie_factory::multi::{all, many_ref};
use cookie_factory::sequence::tuple;
use cookie_factory::*;
use std::io::Write;

pub use cookie_factory::GenError;
pub use rusticata_macros::Serialize;

fn gen_tls_ext_sni_hostname<'a, 'b: 'a, W: Write + 'a>(
    i: &(SNIType, &'b [u8]),
) -> impl SerializeFn<W> + 'a {
    tuple((be_u8((i.0).0 as u8), be_u16(i.1.len() as u16), slice(i.1)))
}

fn length_be_u16<W, F>(f: F) -> impl SerializeFn<W>
where
    W: Write,
    F: SerializeFn<Vec<u8>>,
{
    move |out| {
        // use a temporary buffer
        let (buf, len) = gen(&f, Vec::new())?;
        tuple((be_u16(len as u16), slice(buf)))(out)
    }
}

fn length_be_u24<W, F>(f: F) -> impl SerializeFn<W>
where
    W: Write,
    F: SerializeFn<Vec<u8>>,
{
    move |out| {
        // use a temporary buffer
        let (buf, len) = gen(&f, Vec::new())?;
        tuple((be_u24(len as u32), slice(buf)))(out)
    }
}

fn tagged_extension<W, F>(tag: u16, f: F) -> impl SerializeFn<W>
where
    W: Write,
    F: SerializeFn<Vec<u8>>,
{
    move |out| tuple((be_u16(tag), length_be_u16(&f)))(out)
}

fn gen_tls_ext_sni<'a, W>(m: &'a [(SNIType, &[u8])]) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tagged_extension(
        u16::from(TlsExtensionType::ServerName),
        length_be_u16(many_ref(m, gen_tls_ext_sni_hostname)),
    )
}

fn gen_tls_ext_max_fragment_length<W>(l: u8) -> impl SerializeFn<W>
where
    W: Write,
{
    tagged_extension(u16::from(TlsExtensionType::MaxFragmentLength), be_u8(l))
}

fn gen_tls_named_group<W>(g: NamedGroup) -> impl SerializeFn<W>
where
    W: Write,
{
    be_u16(g.0)
}

fn gen_tls_ext_elliptic_curves<'a, W>(v: &'a [NamedGroup]) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tagged_extension(
        u16::from(TlsExtensionType::SupportedGroups),
        length_be_u16(all(v.iter().map(|&g| gen_tls_named_group(g)))),
    )
}

/// Serialize a single TLS extension
///
/// # Example
///
///  ```rust
///  use cookie_factory::{gen_simple, GenError};
///  use tls_parser::TlsExtension;
///  use tls_parser::gen_tls_extensions;
///
///  fn extensions_to_vec(ext: &[TlsExtension]) -> Result<Vec<u8>, GenError> {
///     gen_simple(gen_tls_extensions(&ext), Vec::new())
///  }
///  ```
///
/// # Note
///
/// **Implementation is incomplete:
/// only a few extensions are supported** (*Work in progress*)
pub fn gen_tls_extension<'a, W>(m: &'a TlsExtension) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    move |out| match m {
        TlsExtension::SNI(ref v) => gen_tls_ext_sni(v)(out),
        TlsExtension::MaxFragmentLength(l) => gen_tls_ext_max_fragment_length(*l)(out),

        TlsExtension::EllipticCurves(ref v) => gen_tls_ext_elliptic_curves(v)(out),
        _ => Err(GenError::NotYetImplemented),
    }
}

/// Serialize a list of TLS extensions
pub fn gen_tls_extensions<'a, W>(m: &'a [TlsExtension]) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    length_be_u16(many_ref(m, gen_tls_extension))
}

fn gen_tls_sessionid<'a, W>(m: &'a Option<&[u8]>) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    move |out| match m {
        None => be_u8(0)(out),
        Some(o) => be_u8(o.len() as u8)(out).and_then(slice(o)),
    }
}

fn maybe_extensions<'a, W>(m: &'a Option<&[u8]>) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    move |out| match m {
        Some(o) => be_u16(o.len() as u16)(out).and_then(slice(o)),
        None => be_u16(0)(out),
    }
}

/// Serialize a ClientHello message
pub fn gen_tls_clienthello<'a, W>(m: &'a TlsClientHelloContents) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tuple((
        be_u8(u8::from(TlsHandshakeType::ClientHello)),
        length_be_u24(tuple((
            be_u16(m.version.0),
            be_u32(m.rand_time),
            slice(m.rand_data), // check that length is 28
            gen_tls_sessionid(&m.session_id),
            be_u16(m.ciphers.len() as u16 * 2),
            all(m.ciphers.iter().map(|cipher| be_u16(cipher.0))),
            be_u8(m.comp.len() as u8),
            all(m.comp.iter().map(|comp| be_u8(comp.0))),
            maybe_extensions(&m.ext),
        ))),
    ))
}

/// Serialize a ServerHello message
pub fn gen_tls_serverhello<'a, W>(m: &'a TlsServerHelloContents) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tuple((
        be_u8(u8::from(TlsHandshakeType::ServerHello)),
        length_be_u24(tuple((
            be_u16(m.version.0),
            be_u32(m.rand_time),
            slice(m.rand_data), // check that length is 28
            gen_tls_sessionid(&m.session_id),
            be_u16(m.cipher.0),
            be_u8(m.compression.0),
            maybe_extensions(&m.ext),
        ))),
    ))
}

/// Serialize a ServerHello (TLS 1.3 draft 18) message
pub fn gen_tls_serverhellodraft18<'a, W>(
    m: &'a TlsServerHelloV13Draft18Contents,
) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tuple((
        be_u8(u8::from(TlsHandshakeType::ServerHello)),
        length_be_u24(tuple((
            be_u16(m.version.0),
            slice(m.random), // check that length is 32
            be_u16(m.cipher.0),
            maybe_extensions(&m.ext),
        ))),
    ))
}

/// Serialize a ClientKeyExchange message, from raw contents
fn gen_tls_clientkeyexchange_unknown<'a, W>(m: &'a [u8]) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tuple((
        be_u8(u8::from(TlsHandshakeType::ClientKeyExchange)),
        length_be_u24(slice(m)),
    ))
}

/// Serialize a ClientKeyExchange message, for DH parameters
fn gen_tls_clientkeyexchange_dh<'a, W>(m: &'a [u8]) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tuple((
        be_u8(u8::from(TlsHandshakeType::ClientKeyExchange)),
        length_be_u24(length_be_u16(slice(m))),
    ))
}

/// Serialize a ClientKeyExchange message, for ECDH parameters
fn gen_tls_clientkeyexchange_ecdh<'a, W>(m: &'a ECPoint) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tuple((
        be_u8(u8::from(TlsHandshakeType::ClientKeyExchange)),
        length_be_u24(tuple((
            // for ECDH, length is only 1 byte
            be_u8(m.point.len() as u8),
            slice(m.point),
        ))),
    ))
}

/// Serialize a ClientKeyExchange message
pub fn gen_tls_clientkeyexchange<'a, W>(
    m: &'a TlsClientKeyExchangeContents,
) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    move |out| match m {
        TlsClientKeyExchangeContents::Unknown(b) => gen_tls_clientkeyexchange_unknown(b)(out),
        TlsClientKeyExchangeContents::Dh(b) => gen_tls_clientkeyexchange_dh(b)(out),
        TlsClientKeyExchangeContents::Ecdh(ref b) => gen_tls_clientkeyexchange_ecdh(b)(out),
    }
}

/// Serialize a HelloRequest message
pub fn gen_tls_hellorequest<W>() -> impl SerializeFn<W>
where
    W: Write,
{
    tuple((be_u8(u8::from(TlsHandshakeType::HelloRequest)), be_u24(0)))
}

/// Serialize a Finished message
pub fn gen_tls_finished<'a, W>(m: &'a [u8]) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tuple((
        be_u8(u8::from(TlsHandshakeType::Finished)),
        length_be_u24(slice(m)),
    ))
}

/// Serialize a TLS handshake message
fn gen_tls_messagehandshake<'a, W>(m: &'a TlsMessageHandshake<'a>) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    move |out| match m {
        TlsMessageHandshake::HelloRequest => gen_tls_hellorequest()(out),
        TlsMessageHandshake::ClientHello(ref m) => gen_tls_clienthello(m)(out),
        TlsMessageHandshake::ServerHello(ref m) => gen_tls_serverhello(m)(out),
        TlsMessageHandshake::ServerHelloV13Draft18(ref m) => gen_tls_serverhellodraft18(m)(out),
        TlsMessageHandshake::ClientKeyExchange(ref m) => gen_tls_clientkeyexchange(m)(out),
        TlsMessageHandshake::Finished(m) => gen_tls_finished(m)(out),
        _ => Err(GenError::NotYetImplemented),
    }
}

impl<'a> Serialize<Vec<u8>> for TlsMessageHandshake<'a> {
    type Error = GenError;
    fn serialize(&self) -> Result<Vec<u8>, Self::Error> {
        gen_simple(gen_tls_messagehandshake(self), Vec::new())
    }
}

/// Serialize a ChangeCipherSpec message
pub fn gen_tls_changecipherspec<W>() -> impl SerializeFn<W>
where
    W: Write,
{
    be_u8(u8::from(TlsRecordType::ChangeCipherSpec))
}

/// Serialize a TLS message
///
/// # Example
///
///  ```rust
///  use cookie_factory::{gen_simple, GenError};
///  use tls_parser::TlsMessage;
///  use tls_parser::gen_tls_message;
///
///  fn tls_message_to_vec(msg: &TlsMessage) -> Result<Vec<u8>, GenError> {
///     gen_simple(gen_tls_message(&msg), Vec::new())
///  }
///  ```
pub fn gen_tls_message<'a, W>(m: &'a TlsMessage<'a>) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    move |out| match m {
        TlsMessage::Handshake(ref m) => gen_tls_messagehandshake(m)(out),
        TlsMessage::ChangeCipherSpec => gen_tls_changecipherspec()(out),
        _ => Err(GenError::NotYetImplemented),
    }
}

impl<'a> Serialize<Vec<u8>> for TlsMessage<'a> {
    type Error = GenError;
    fn serialize(&self) -> Result<Vec<u8>, Self::Error> {
        gen_simple(gen_tls_message(self), Vec::new())
    }
}

/// Serialize a TLS plaintext record
///
/// # Example
///
///  ```rust
///  use cookie_factory::{gen_simple, GenError};
///  use tls_parser::TlsPlaintext;
///  use tls_parser::gen_tls_plaintext;
///
///  fn tls_message_to_vec(rec: &TlsPlaintext) -> Result<Vec<u8>, GenError> {
///     gen_simple(gen_tls_plaintext(&rec), Vec::new())
///  }
///  ```
pub fn gen_tls_plaintext<'a, W>(p: &'a TlsPlaintext) -> impl SerializeFn<W> + 'a
where
    W: Write + 'a,
{
    tuple((
        be_u8(p.hdr.record_type.0),
        be_u16(p.hdr.version.0),
        length_be_u16(all(p.msg.iter().map(|m| gen_tls_message(m)))),
    ))
}

impl<'a> Serialize<Vec<u8>> for TlsPlaintext<'a> {
    type Error = GenError;
    fn serialize(&self) -> Result<Vec<u8>, Self::Error> {
        gen_simple(gen_tls_plaintext(self), Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_extensions::parse_tls_extension;
    use hex_literal::hex;

    const CH_DHE: &[u8] = include_bytes!("../assets/client_hello_dhe.bin");

    #[test]
    fn serialize_tagged_extension() {
        let expected = &hex!("12 34 00 02 00 01");
        let res =
            gen_simple(tagged_extension(0x1234, be_u16(1)), Vec::new()).expect("serialize failed");
        assert_eq!(&res, expected);
    }

    #[test]
    fn serialize_extension_sni() {
        let raw_sni = &hex!(
            "
00 00 00 14 00 12 00 00 0f 63 2e 64 69 73 71 75
73 63 64 6e 2e 63 6f 6d
"
        );
        let (_, ext) = parse_tls_extension(raw_sni).expect("could not parse sni extension");
        if let TlsExtension::SNI(sni) = ext {
            let res = gen_simple(gen_tls_ext_sni(&sni), Vec::new())
                .expect("could not serialize sni extension");
            assert_eq!(&res, raw_sni);
        } else {
            panic!("parsed extension has wrong type");
        }
    }

    #[test]
    fn serialize_tls_extensions() {
        let ext = vec![TlsExtension::SNI(vec![(
            SNIType::HostName,
            b"www.google.com",
        )])];

        let res = gen_simple(gen_tls_extensions(&ext), Vec::new())
            .expect("could not serialize extensions");
        let v = [
            0x00, 0x17, // Extensions length (total)
            0x00, 0x00, // SNI tag
            0x00, 0x13, // SNI ext length
            0x00, 0x11, // SNI list length
            // element 0:
            0x00, // type
            0x00, 0x0e, // length
            0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        assert_eq!(&res, &v);
    }

    #[test]
    fn serialize_plaintext() {
        let rand_data = [
            0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, 0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f,
            0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8, 0xa9, 0x03, 0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4,
        ];
        let ciphers = vec![
            0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x00a5, 0x00a3, 0x00a1, 0x009f, 0x006b,
            0x006a, 0x0069, 0x0068, 0x0039, 0x0038, 0x0037, 0x0036, 0x0088, 0x0087, 0x0086, 0x0085,
            0xc032, 0xc02e, 0xc02a, 0xc026, 0xc00f, 0xc005, 0x009d, 0x003d, 0x0035, 0x0084, 0xc02f,
            0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x00a4, 0x00a2, 0x00a0, 0x009e, 0x0067, 0x0040,
            0x003f, 0x003e, 0x0033, 0x0032, 0x0031, 0x0030, 0x009a, 0x0099, 0x0098, 0x0097, 0x0045,
            0x0044, 0x0043, 0x0042, 0xc031, 0xc02d, 0xc029, 0xc025, 0xc00e, 0xc004, 0x009c, 0x003c,
            0x002f, 0x0096, 0x0041, 0xc011, 0xc007, 0xc00c, 0xc002, 0x0005, 0x0004, 0xc012, 0xc008,
            0x0016, 0x0013, 0x0010, 0x000d, 0xc00d, 0xc003, 0x000a, 0x00ff,
        ];
        let comp = vec![TlsCompressionID(0x00)];

        let expected = TlsPlaintext {
            hdr: TlsRecordHeader {
                record_type: TlsRecordType::Handshake,
                version: TlsVersion::Tls10,
                len: 215,
            },
            msg: vec![TlsMessage::Handshake(TlsMessageHandshake::ClientHello(
                TlsClientHelloContents {
                    version: TlsVersion::Tls12,
                    rand_time: 0xb29d_d787,
                    rand_data: &rand_data,
                    session_id: None,
                    ciphers: ciphers.iter().map(|&x| TlsCipherSuiteID(x)).collect(),
                    comp,
                    ext: Some(&[]),
                },
            ))],
        };

        let res = expected
            .serialize()
            .expect("Could not serialize plaintext message");
        let (_, res_reparse) =
            parse_tls_plaintext(&res).expect("Could not parse gen_tls_plaintext output");
        assert_eq!(res_reparse, expected);
    }

    #[test]
    fn serialize_hellorequest() {
        let m = TlsMessageHandshake::HelloRequest;

        let res = m.serialize().expect("Could not serialize messages");
        let v = [0, 0, 0, 0];
        assert_eq!(&v[..], &res[..]);
    }

    #[test]
    fn serialize_tls_ext() {
        let ext = TlsExtension::SNI(vec![(SNIType::HostName, b"www.google.com")]);

        let res =
            gen_simple(gen_tls_extension(&ext), Vec::new()).expect("Could not serialize messages");
        let v = [
            0x00, 0x00, // SNI tag
            0x00, 0x13, // SNI ext length
            0x00, 0x11, // SNI list length
            // element 0:
            0x00, // type
            0x00, 0x0e, // length
            0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        assert_eq!(&v[..], &res[..]);
    }

    #[test]
    fn serialize_clienthello() {
        let rand_data = [
            0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, 0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f,
            0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8, 0xa9, 0x03, 0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4,
        ];
        let ciphers = vec![0xc030, 0xc02c];
        let comp = vec![TlsCompressionID(0x00)];

        let m = TlsMessageHandshake::ClientHello(TlsClientHelloContents {
            version: TlsVersion::Tls12,
            rand_time: 0xb29d_d787,
            rand_data: &rand_data,
            session_id: None,
            ciphers: ciphers.iter().map(|&x| TlsCipherSuiteID(x)).collect(),
            comp,
            ext: None,
        });

        let res = m.serialize().expect("Could not serialize messages");
        let v = [
            0x01, 0x00, 0x00, 0x2d, 0x03, 0x03, // type, length, version
            0xb2, 0x9d, 0xd7, 0x87, // random time
            0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, // random data
            0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f, 0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8, 0xa9, 0x03,
            0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4, 0x00, // session ID
            0x00, 0x04, 0xc0, 0x30, 0xc0, 0x2c, // ciphers
            0x01, 0x00, // compression
            0x00, 0x00, // extensions length
        ];
        assert_eq!(&v[..], &res[..]);
    }

    #[test]
    fn serialize_serverhello() {
        let rand_data = [
            0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, 0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f,
            0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8, 0xa9, 0x03, 0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4,
        ];

        let m = TlsMessageHandshake::ServerHello(TlsServerHelloContents {
            version: TlsVersion::Tls12,
            rand_time: 0xb29d_d787,
            rand_data: &rand_data,
            session_id: None,
            cipher: TlsCipherSuiteID(0xc030),
            compression: TlsCompressionID(0),
            ext: None,
        });

        let res = gen_simple(gen_tls_messagehandshake(&m), Vec::new())
            .expect("Could not serialize message");
        let v = [
            0x02, 0x00, 0x00, 0x28, 0x03, 0x03, // type, length, version
            0xb2, 0x9d, 0xd7, 0x87, // random time
            0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, // random data
            0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f, 0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8, 0xa9, 0x03,
            0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4, 0x00, // session ID
            0xc0, 0x30, // cipher
            0x00, // compression
            0x00, 0x00, // extensions length
        ];
        assert_eq!(&v[..], &res[..]);
    }

    #[test]
    fn read_serialize_clienthello_dhe() {
        let (_, record) = parse_tls_plaintext(CH_DHE).expect("parsing failed");
        let res = gen_simple(gen_tls_plaintext(&record), Vec::new())
            .expect("Could not serialize message");
        let (_, record2) = parse_tls_plaintext(&res).expect("re-parsing failed");
        assert_eq!(record, record2);
    }
}
