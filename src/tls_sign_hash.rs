use nom::{be_u8,be_u16,IResult};

/// Hash algorithms, as defined in [RFC5246]
enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum HashAlgorithm {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
}
}

/// Signature algorithms, as defined in [RFC5246]
enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum SignAlgorithm {
    Anonymous = 0,
    Rsa = 1,
    Dsa = 2,
    Ecdsa = 3,
}
}

#[derive(PartialEq)]
pub struct HashSignAlgorithm {
    pub hash: u8,
    pub sign: u8,
}

/// Signature algorithms, as defined in [draft-ietf-tls-tls13-18]
enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum SignatureScheme {
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0203,

    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,

    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,

    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,

    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,

    Ed25519 = 0x0807,
    Ed448 = 0x0808,
}
}


/// DigitallySigned structure from [RFC2246] section 4.7
/// has no algorithm definition.
/// This should be deprecated in favor if
/// DigitallySigned structure from [RFC5246] section 4.7
#[derive(PartialEq)]
pub struct DigitallySigned<'a> {
    pub alg: Option<HashSignAlgorithm>,
    // pub alg: Option<u16>, // SignatureScheme
    pub data: &'a[u8],
}






named!(pub parse_digitally_signed_old<DigitallySigned>,
    map!(
        length_bytes!(be_u16),
        |d| { DigitallySigned{ alg:None, data:d } }
    )
);

named!(pub parse_digitally_signed<DigitallySigned>,
    do_parse!(
        h: be_u8 >>
        s: be_u8 >>
        d: length_bytes!(be_u16) >>
        ( DigitallySigned{
            alg: Some( HashSignAlgorithm{ hash:h, sign:s } ),
            data: d,
        })
    )
);

/// Parse DigitallySigned object, depending on the `ext` parameter which should
/// be true if the TLS client has sent the `signature_algorithms` extension
pub fn parse_content_and_signature<'a,F,T:'a>(i: &'a[u8], fun: F, ext: bool) -> IResult<&'a[u8],(T,DigitallySigned)>
  where F: Fn(&'a[u8]) -> IResult<&[u8],T>
{
    if ext {
        pair!(i,fun,parse_digitally_signed)
    } else {
        pair!(i,fun,parse_digitally_signed_old)
    }
}
