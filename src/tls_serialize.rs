#[cfg(feature = "serialize")]
pub mod serialize {

    use crate::tls::*;
    use crate::tls_ec::{ECPoint, NamedGroup};
    use crate::tls_extensions::{SNIType, TlsExtension, TlsExtensionType};
    use cookie_factory::gen::{set_be_u16, set_be_u8};
    use cookie_factory::*;

    #[macro_export]
    macro_rules! gen_tagged_extension(
    (($i:expr, $idx:expr), $tag:expr, $submac:ident!( $($args:tt)* )) => (
        do_gen!(($i,$idx),
                   gen_be_u16!($tag) >>
            ofs:   gen_skip!(2) >>
            start: $submac!( $($args)* ) >>
            end:   gen_at_offset!(ofs,gen_be_u16!((end-start) as u16))
        )
    );
    (($i:expr, $idx:expr), $tag:expr, $f:ident( $($args:tt)* )) => (
        gen_tagged_extension!(($i,$idx), $tag, $gen_call!($f( $($args)* )))
    );
    ($x:expr, $tag:expr, $submac:ident!( $($args:tt)* )) => (
        gen_tagged_extension!(($x.0, $x.1), $tag, $submac!( $($args)* )) );
    ($x:expr, $tag:expr, $f:ident( $($args:tt)* )) => (
        gen_tagged_extension!(($x.0, $x.1), $tag, $f( $($args)* )) );
);

    #[macro_export]
    macro_rules! gen_length_bytes_be_u16(
    (($i:expr, $idx:expr), $submac:ident!( $($args:tt)* )) => (
        do_gen!(($i,$idx),
            ofs:   gen_skip!(2) >>
            start: $submac!( $($args)* ) >>
            end:   gen_at_offset!(ofs,gen_be_u16!((end-start) as u16))
        )
    );
    (($i:expr, $idx:expr), $f:ident( $($args:tt)* )) => (
        gen_length_bytes_be_u16!(($i,$idx), $gen_call!($f( $($args)* )))
    );
    ($x:ident, $submac:ident!( $($args:tt)* )) => ( gen_length_bytes_be_u16!(($x.0,$x.1), $submac!( $($args)* )));
    ($x:ident, $f:ident( $($args:tt)* )) => ( gen_length_bytes_be_u16!(($x.0,$x.1), $f( $($args)* )));
);

    #[macro_export]
    macro_rules! gen_many_deref(
    (($i:expr, $idx:expr), $l:expr, $f:expr) => (
        $l.into_iter().fold(
            Ok(($i,$idx)),
            |r,&v| {
                match r {
                    Err(e) => Err(e),
                    Ok(x) => { $f(x, (*v)) },
                }
            }
        )
    );
);

    #[inline]
    pub fn gen_tls_named_group<'a>(
        x: (&'a mut [u8], usize),
        g: NamedGroup,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        set_be_u16(x, g.0)
    }

    #[inline]
    pub fn gen_tls_ec_point<'a>(
        x: (&'a mut [u8], usize),
        p: ECPoint,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
            gen_be_u8!(p.point.len() as u8) >>
            gen_slice!(p.point)
        }
    }

    pub fn gen_tls_ext_sni_hostname<'a, 'b>(
        x: (&'a mut [u8], usize),
        h: &(SNIType, &'b [u8]),
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
            gen_be_u8!((h.0).0 as u8) >>
            gen_be_u16!(h.1.len() as u16) >>
            gen_slice!(h.1)
        }
    }

    #[inline]
    pub fn gen_tls_ext_sni<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b Vec<(SNIType, &'b [u8])>,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        gen_tagged_extension!(x, 0x0000, gen_many_ref!(m, gen_tls_ext_sni_hostname))
    }

    #[inline]
    pub fn gen_tls_ext_max_fragment_length<'a, 'b>(
        x: (&'a mut [u8], usize),
        l: u8,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        gen_tagged_extension!(x, 0x0001, gen_be_u8!(l))
    }

    #[inline]
    pub fn gen_tls_ext_elliptic_curves<'a, 'b>(
        x: (&'a mut [u8], usize),
        v: &'b Vec<NamedGroup>,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        gen_tagged_extension!(
            x,
            u16::from(TlsExtensionType::SupportedGroups),
            gen_length_bytes_be_u16!(gen_many_byref!(v, gen_tls_named_group))
        )
    }

    pub fn gen_tls_extension<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b TlsExtension,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        match m {
            &TlsExtension::SNI(ref v) => gen_tls_ext_sni(x, v),
            &TlsExtension::MaxFragmentLength(l) => gen_tls_ext_max_fragment_length(x, l),

            &TlsExtension::EllipticCurves(ref v) => gen_tls_ext_elliptic_curves(x, v),

            _ => Err(GenError::NotYetImplemented),
        }
    }

    pub fn gen_tls_extensions<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b Vec<TlsExtension>,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        gen_length_bytes_be_u16!(x, gen_many_ref!(m, gen_tls_extension))
    }

    #[inline]
    pub fn gen_tls_sessionid<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &Option<&'b [u8]>,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        match m {
            &None => gen_be_u8!(x, 0),
            &Some(o) => {
                do_gen! {
                    x,
                    gen_be_u8!(o.len() as u8) >>
                    gen_slice!(o)
                }
            }
        }
    }

    pub fn gen_tls_hellorequest<'a>(
        x: (&'a mut [u8], usize),
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
            gen_be_u8!(u8::from(TlsHandshakeType::HelloRequest)) >>
            gen_be_u24!(0)
        }
    }

    fn gen_maybe_extensions<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b Option<&[u8]>,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        if let Some(ext) = m {
            do_gen! {
                x,
                gen_be_u16!(ext.len() as u16) >>
                gen_slice!(ext)
            }
        } else {
            gen_be_u16!(x, 0)
        }
    }

    pub fn gen_tls_clienthello<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b TlsClientHelloContents,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
                     gen_be_u8!(u8::from(TlsHandshakeType::ClientHello)) >>
            ofs_len: gen_skip!(3) >>
            start:   gen_be_u16!(u16::from(m.version)) >>
                     gen_be_u32!(m.rand_time) >>
                     gen_copy!(m.rand_data,28) >>
                     gen_tls_sessionid(&m.session_id) >>
                     gen_be_u16!((m.ciphers.len()*2) as u16) >>
                     gen_many_deref!(&m.ciphers,set_be_u16) >>
                     gen_be_u8!(m.comp.len() as u8) >>
                     gen_many_deref!(&m.comp,set_be_u8) >>
                     gen_maybe_extensions(&m.ext) >>
            end:     gen_at_offset!(ofs_len,gen_be_u24!((end-start) as u32))
        }
    }

    pub fn gen_tls_serverhello<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b TlsServerHelloContents,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
                     gen_be_u8!(u8::from(TlsHandshakeType::ServerHello)) >>
            ofs_len: gen_skip!(3) >>
            start:   gen_be_u16!(u16::from(m.version)) >>
                     gen_be_u32!(m.rand_time) >>
                     gen_copy!(m.rand_data,28) >>
                     gen_tls_sessionid(&m.session_id) >>
                     gen_be_u16!(*m.cipher) >>
                     gen_be_u8!(*m.compression) >>
                     gen_maybe_extensions(&m.ext) >>
            end:     gen_at_offset!(ofs_len,gen_be_u24!((end-start) as u32))
        }
    }

    pub fn gen_tls_serverhellov13draft18<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b TlsServerHelloV13Draft18Contents,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
                     gen_be_u8!(u8::from(TlsHandshakeType::ServerHello)) >>
            ofs_len: gen_skip!(3) >>
            start:   gen_copy!(m.random,32) >>
                     gen_be_u16!(*m.cipher) >>
                     gen_cond!(m.ext.is_some(),gen_slice!(m.ext.unwrap())) >>
            end:     gen_at_offset!(ofs_len,gen_be_u24!((end-start) as u32))
        }
    }

    pub fn gen_tls_finished<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b [u8],
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
                     gen_be_u8!(u8::from(TlsHandshakeType::ServerHello)) >>
            ofs_len: gen_skip!(3) >>
            start:   gen_slice!(m) >>
            end:     gen_at_offset!(ofs_len,gen_be_u24!((end-start) as u32))
        }
    }

    pub fn gen_tls_clientkeyexchange_unknown<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b [u8],
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
            gen_be_u8!(u8::from(TlsHandshakeType::ClientKeyExchange)) >>
            gen_be_u24!(m.len() as u32) >>
            gen_slice!(m)
        }
    }

    pub fn gen_tls_clientkeyexchange_dh<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b [u8],
    ) -> Result<(&'a mut [u8], usize), GenError> {
        // for DH, length is 2 bytes
        do_gen! {
            x,
                     gen_be_u8!(u8::from(TlsHandshakeType::ClientKeyExchange)) >>
            ofs_len: gen_skip!(3) >>
            start:   gen_be_u16!(m.len() as u16) >>
                     gen_slice!(m) >>
            end:     gen_at_offset!(ofs_len,gen_be_u24!((end-start) as u32))
        }
    }

    pub fn gen_tls_clientkeyexchange_ecdh<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b ECPoint,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        // for ECDH, length is only 1 byte
        do_gen! {
            x,
                     gen_be_u8!(u8::from(TlsHandshakeType::ClientKeyExchange)) >>
            ofs_len: gen_skip!(3) >>
            start:   gen_skip!(1) >>
            s2:      gen_slice!(m.point) >>
            end:     gen_at_offset!(start,gen_be_u8!((end-s2) as u8)) >>
                     gen_at_offset!(ofs_len,gen_be_u24!((end-start) as u32))
        }
    }

    pub fn gen_tls_clientkeyexchange<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b TlsClientKeyExchangeContents,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        match m {
            &TlsClientKeyExchangeContents::Unknown(ref b) => {
                gen_tls_clientkeyexchange_unknown(x, b)
            }
            &TlsClientKeyExchangeContents::Dh(ref b) => gen_tls_clientkeyexchange_dh(x, b),
            &TlsClientKeyExchangeContents::Ecdh(ref b) => gen_tls_clientkeyexchange_ecdh(x, b),
        }
    }

    pub fn gen_tls_messagehandshake<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b TlsMessageHandshake,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        match m {
            &TlsMessageHandshake::HelloRequest => gen_tls_hellorequest(x),
            &TlsMessageHandshake::ClientHello(ref m) => gen_tls_clienthello(x, m),
            &TlsMessageHandshake::ServerHello(ref m) => gen_tls_serverhello(x, m),
            &TlsMessageHandshake::ServerHelloV13Draft18(ref m) => {
                gen_tls_serverhellov13draft18(x, m)
            }
            &TlsMessageHandshake::ClientKeyExchange(ref m) => gen_tls_clientkeyexchange(x, m),
            &TlsMessageHandshake::Finished(ref m) => gen_tls_finished(x, m),
            _ => Err(GenError::NotYetImplemented),
        }
    }

    #[inline]
    pub fn gen_tls_changecipherspec<'a>(
        x: (&'a mut [u8], usize),
    ) -> Result<(&'a mut [u8], usize), GenError> {
        gen_be_u8!(x, 1)
    }

    pub fn gen_tls_message<'a, 'b>(
        x: (&'a mut [u8], usize),
        m: &'b TlsMessage,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        match m {
            &TlsMessage::Handshake(ref m) => gen_tls_messagehandshake(x, m),
            &TlsMessage::ChangeCipherSpec => gen_tls_changecipherspec(x),
            _ => Err(GenError::NotYetImplemented),
        }
    }

    /// Write a TlsPlaintext record to the input slice
    ///
    /// if p.hdr.len is 0, compute the real size of the record
    /// otherwise, use the provided length
    pub fn gen_tls_plaintext<'a, 'b>(
        x: (&'a mut [u8], usize),
        p: &'b TlsPlaintext,
    ) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen! {
            x,
                     gen_be_u8!(u8::from(p.hdr.record_type)) >>
                     gen_be_u16!(p.hdr.version.0) >>
            ofs_len: gen_be_u16!(p.hdr.len) >>
            // gen_skip!(2) >>
            start:   gen_many_ref!(&p.msg,gen_tls_message) >>
            end:     gen_cond!(p.hdr.len == 0,
                               gen_at_offset!(ofs_len,gen_be_u16!((end-start) as u16)))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn serialize_plaintext() {
            let rand_data = [
                0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, 0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f,
                0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8, 0xa9, 0x03, 0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4,
            ];
            let ciphers = vec![
                0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x00a5, 0x00a3, 0x00a1, 0x009f,
                0x006b, 0x006a, 0x0069, 0x0068, 0x0039, 0x0038, 0x0037, 0x0036, 0x0088, 0x0087,
                0x0086, 0x0085, 0xc032, 0xc02e, 0xc02a, 0xc026, 0xc00f, 0xc005, 0x009d, 0x003d,
                0x0035, 0x0084, 0xc02f, 0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x00a4, 0x00a2,
                0x00a0, 0x009e, 0x0067, 0x0040, 0x003f, 0x003e, 0x0033, 0x0032, 0x0031, 0x0030,
                0x009a, 0x0099, 0x0098, 0x0097, 0x0045, 0x0044, 0x0043, 0x0042, 0xc031, 0xc02d,
                0xc029, 0xc025, 0xc00e, 0xc004, 0x009c, 0x003c, 0x002f, 0x0096, 0x0041, 0xc011,
                0xc007, 0xc00c, 0xc002, 0x0005, 0x0004, 0xc012, 0xc008, 0x0016, 0x0013, 0x0010,
                0x000d, 0xc00d, 0xc003, 0x000a, 0x00ff,
            ];
            let comp = vec![TlsCompressionID(0x00)];

            let expected = TlsPlaintext {
                hdr: TlsRecordHeader {
                    record_type: TlsRecordType::Handshake,
                    version: TlsVersion::Tls10,
                    len: 213,
                },
                msg: vec![TlsMessage::Handshake(TlsMessageHandshake::ClientHello(
                    TlsClientHelloContents {
                        version: TlsVersion::Tls12,
                        rand_time: 0xb29dd787,
                        rand_data: &rand_data,
                        session_id: None,
                        ciphers: ciphers.iter().map(|&x| TlsCipherSuiteID(x)).collect(),
                        comp: comp,
                        ext: None,
                    },
                ))],
            };

            {
                let mut mem: [u8; 218] = [0; 218];
                let s = &mut mem[..];

                let res = gen_tls_plaintext((s, 0), &expected);
                match res {
                    Ok((b, _)) => {
                        let res_reparse = parse_tls_plaintext(b);
                        assert_eq!(res_reparse, Ok((&b""[..], expected)));
                    }
                    Err(e) => println!("Error: {:?}", e),
                };
            }
        }

        #[test]
        fn serialize_hellorequest() {
            let mut mem: [u8; 256] = [0; 256];
            let s = &mut mem[..];
            let m = TlsMessageHandshake::HelloRequest;

            let res = gen_tls_messagehandshake((s, 0), &m);
            match res {
                Ok((b, _)) => {
                    let v = [0, 0, 0, 0];
                    assert_eq!(&b[..v.len()], v);
                }
                Err(e) => println!("Error: {:?}", e),
            };
        }

        #[test]
        fn serialize_tls_ext() {
            let mut mem: [u8; 256] = [0; 256];
            let s = &mut mem[..];
            let ext = vec![TlsExtension::SNI(vec![(
                SNIType::HostName,
                b"www.google.com",
            )])];

            let res = gen_many_ref!((s, 0), ext, gen_tls_extension);
            match res {
                Ok((b, idx)) => {
                    let v = [
                        0x00, 0x00, // SNI tag
                        0x00, 0x11, // SNI ext length
                        // element 0:
                        0x00, // type
                        0x00, 0x0e, // length
                        0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63,
                        0x6f, 0x6d,
                    ];
                    assert_eq!(idx, v.len());
                    assert_eq!(&b[..v.len()], &v[..]);
                }
                Err(e) => println!("Error: {:?}", e),
            };
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
                rand_time: 0xb29dd787,
                rand_data: &rand_data,
                session_id: None,
                ciphers: ciphers.iter().map(|&x| TlsCipherSuiteID(x)).collect(),
                comp: comp,
                ext: None,
            });

            let mut mem: [u8; 256] = [0; 256];
            let s = &mut mem[..];

            let res = gen_tls_messagehandshake((s, 0), &m);
            match res {
                Ok((b, idx)) => {
                    let v = [
                        0x01, 0x00, 0x00, 0x2d, 0x03, 0x03, // type, length, version
                        0xb2, 0x9d, 0xd7, 0x87, // random time
                        0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, // random data
                        0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f, 0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8,
                        0xa9, 0x03, 0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4, 0x00, // session ID
                        0x00, 0x04, 0xc0, 0x30, 0xc0, 0x2c, // ciphers
                        0x01, 0x00, // compression
                        0x00, 0x00, // extensions length
                    ];
                    assert_eq!(idx, v.len());
                    assert_eq!(&b[..v.len()], &v[..]);
                }
                Err(e) => println!("Error: {:?}", e),
            };
        }

        #[test]
        fn serialize_serverhello() {
            let rand_data = [
                0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, 0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f,
                0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8, 0xa9, 0x03, 0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4,
            ];

            let m = TlsMessageHandshake::ServerHello(TlsServerHelloContents {
                version: TlsVersion::Tls12,
                rand_time: 0xb29dd787,
                rand_data: &rand_data,
                session_id: None,
                cipher: TlsCipherSuiteID(0xc030),
                compression: TlsCompressionID(0),
                ext: None,
            });

            let mut mem: [u8; 256] = [0; 256];
            let s = &mut mem[..];

            let res = gen_tls_messagehandshake((s, 0), &m);
            match res {
                Ok((b, idx)) => {
                    let v = [
                        0x02, 0x00, 0x00, 0x28, 0x03, 0x03, // type, length, version
                        0xb2, 0x9d, 0xd7, 0x87, // random time
                        0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, // random data
                        0x9a, 0xcf, 0xb7, 0xa3, 0x82, 0x1f, 0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8,
                        0xa9, 0x03, 0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4, 0x00, // session ID
                        0xc0, 0x30, // cipher
                        0x00, // compression
                        0x00, 0x00, // extensions length
                    ];
                    assert_eq!(idx, v.len());
                    assert_eq!(&b[..v.len()], &v[..]);
                }
                Err(e) => println!("Error: {:?}", e),
            };
        }
    }
}
