#[macro_use]
extern crate pretty_assertions;

extern crate nom;
extern crate tls_parser;

mod tls_extensions {
    use tls_parser::*;

    #[rustfmt::skip]
static CLIENT_EXTENSIONS1: &[u8] = &[
    0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00,
    0x0a, 0x00, 0x1c, 0x00, 0x1a, 0x00, 0x17, 0x00, 0x19, 0x00, 0x1c, 0x00, 0x1b, 0x00, 0x18, 0x00,
    0x1a, 0x00, 0x16, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x09, 0x00, 0x0a, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
    0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03,
    0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0f, 0x00, 0x01, 0x01
];

    #[test]
    fn test_tls_extensions() {
        let empty = &b""[..];
        let bytes = CLIENT_EXTENSIONS1;
        let ec_point_formats = &[0, 1, 2];
        let ext1 = &[0, 0, 0, 0];
        let ecc: Vec<_> = vec![23, 25, 28, 27, 24, 26, 22, 14, 13, 11, 12, 9, 10]
            .iter()
            .map(|&x| NamedGroup(x))
            .collect();
        let expected = Ok((
            empty,
            vec![
                TlsExtension::SNI(vec![(SNIType::HostName, b"www.google.com")]),
                TlsExtension::EcPointFormats(ec_point_formats),
                TlsExtension::EllipticCurves(ecc),
                TlsExtension::SessionTicket(empty),
                TlsExtension::SignatureAlgorithms(vec![
                    0x0601, 0x0602, 0x0603, 0x0501, 0x0502, 0x0503, 0x0401, 0x0402, 0x0403, 0x0301,
                    0x0302, 0x0303, 0x0201, 0x0202, 0x0203,
                ]),
                TlsExtension::StatusRequest(Some((CertificateStatusType::OCSP, ext1))),
                TlsExtension::Heartbeat(1),
            ],
        ));

        let res = parse_tls_extensions(bytes);

        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_max_fragment_length() {
        let empty = &b""[..];
        let bytes = &[0x00, 0x01, 0x00, 0x01, 0x04];
        let expected = Ok((empty, TlsExtension::MaxFragmentLength(4)));

        let res = parse_tls_extension(bytes);

        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_alpn() {
        let empty = &b""[..];
        let bytes = &[
            0x00, 0x10, 0x00, 0x29, 0x00, 0x27, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x36, 0x05, 0x68,
            0x32, 0x2d, 0x31, 0x35, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x34, 0x02, 0x68, 0x32, 0x08,
            0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x2e, 0x31, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f,
            0x31, 0x2e, 0x31,
        ];
        let expected = Ok((
            empty,
            TlsExtension::ALPN(vec![
                b"h2-16",
                b"h2-15",
                b"h2-14",
                b"h2",
                b"spdy/3.1",
                b"http/1.1",
            ]),
        ));

        let res = parse_tls_extension(bytes);

        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_encrypt_then_mac() {
        let empty = &b""[..];
        let bytes = &[0x00, 0x16, 0x00, 0x00];
        let expected = Ok((empty, TlsExtension::EncryptThenMac));

        let res = parse_tls_extension(bytes);

        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_extended_master_secret() {
        let empty = &b""[..];
        let bytes = &[0x00, 0x17, 0x00, 0x00];
        let expected = Ok((empty, TlsExtension::ExtendedMasterSecret));

        let res = parse_tls_extension(bytes);

        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_npn() {
        let empty = &b""[..];
        let bytes = &[0x33, 0x74, 0x00, 0x00];
        let expected = Ok((empty, TlsExtension::NextProtocolNegotiation));

        let res = parse_tls_extension(bytes);

        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_list() {
        let empty = &b""[..];
        let bytes = &[0, 5, 0, 0, 0, 23, 0, 0, 255, 1, 0, 1, 0];
        let expected = Ok((
            empty,
            vec![
                TlsExtension::StatusRequest(None),
                TlsExtension::ExtendedMasterSecret,
                TlsExtension::RenegotiationInfo(&[]),
            ],
        ));

        let res = parse_tls_extensions(bytes);
        println!("{:?}", res);

        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_keyshare_helloretryrequest() {
        let empty = &b""[..];
        let bytes = &[
            0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xa2, 0x4e, 0x84, 0xfa, 0x82, 0x63,
            0xf8, 0xff, 0x20, 0x7a, 0x79, 0x82, 0xfd, 0x34, 0x12, 0xfc, 0xae, 0x8d, 0xd8, 0xe3,
            0x1e, 0xf4, 0x5d, 0xe6, 0x61, 0x09, 0x3b, 0x7f, 0xa5, 0x81, 0x12, 0x63, 0x00, 0x2b,
            0x00, 0x02, 0x7f, 0x17,
        ];
        let expected = Ok((
            empty,
            vec![
                TlsExtension::KeyShare(&bytes[4..40]),
                TlsExtension::SupportedVersions(vec![TlsVersion(0x7f17)]),
            ],
        ));

        let res = parse_tls_extensions(bytes);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_signed_certificate_timestamp() {
        let empty = &b""[..];
        let bytes = &[0x00, 0x12, 0x00, 0x00];
        let expected = Ok((empty, TlsExtension::SignedCertificateTimestamp(None)));

        let res = parse_tls_extension(bytes);

        assert_eq!(res, expected);
    }

    #[test]
    fn test_tls_extension_grease() {
        let empty = &b""[..];
        let bytes = &[0x3a, 0x3a, 0x00, 0x01, 0x00];
        let expected = TlsExtension::Grease(0x3a3a, &[0x00]);

        let res = parse_tls_extension(bytes);

        assert_eq!(res, Ok((empty, expected)));
    }

    const ESNI: &[u8] = include_bytes!("../assets/esni.bin");

    #[test]
    fn test_tls_extension_esni() {
        let res = parse_tls_extension(ESNI).expect("Parsing eSNI failed");
        match res.1 {
            TlsExtension::EncryptedServerName {
                ciphersuite, group, ..
            } => {
                assert_eq!(ciphersuite.0, 0x1301);
                assert_eq!(group.0, 0x1d);
            }
            _ => panic!("Wrong extension type (expected eSNI"),
        }
    }

    #[test]
    fn test_tls_extension_record_size_limit() {
        let empty = &b""[..];
        let bytes = &[0x00, 0x1c, 0x00, 0x02, 0x40, 0x01];
        let expected = TlsExtension::RecordSizeLimit(16385);
        let res = parse_tls_extension(bytes);
        assert_eq!(res, Ok((empty, expected)));
    }
} // mod tls_extensions
