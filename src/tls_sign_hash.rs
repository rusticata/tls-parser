use nom::IResult;
use nom::number::streaming::{be_u8, be_u16};

/// Hash algorithms, as defined in [RFC5246]
#[derive(Debug, PartialEq, Eq)]
pub struct HashAlgorithm(pub u8);

newtype_enum! {
impl display HashAlgorithm {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
    Intrinsic = 8, // [RFC8422]
}
}

/// Signature algorithms, as defined in [RFC5246]
#[derive(Debug, PartialEq, Eq)]
pub struct SignAlgorithm(pub u8);

newtype_enum! {
impl display SignAlgorithm {
    Anonymous = 0,
    Rsa = 1,
    Dsa = 2,
    Ecdsa = 3,
    Ed25519 = 7, // [RFC8422]
    Ed448 = 8, // [RFC8422]
}
}

#[derive(PartialEq)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub sign: SignAlgorithm,
}

/// Signature algorithms, as defined in [RFC8446] 4.2.3
#[derive(Debug, PartialEq, Eq)]
pub struct SignatureScheme(pub u16);

newtype_enum! {
impl display SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    ed25519 = 0x0807,
    ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    /* Legacy algorithms */
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,
}
}

impl SignatureScheme {
    pub fn is_reserved(&self) -> bool {
        self.0 >= 0xfe00 && self.0 < 0xff00
    }

    /// Get Hash algorithm (for tls <= 1.2) for legacy extension format
    pub fn hash_alg(&self) -> u8 {
        ((self.0 >> 8) & 0xff) as u8
    }

    /// Get Signature algorithm (for tls <= 1.2) for legacy extension format
    pub fn sign_alg(&self) -> u8 {
        (self.0 & 0xff) as u8
    }
}


/// DigitallySigned structure from [RFC2246] section 4.7
/// has no algorithm definition.
/// This should be deprecated in favor if
/// DigitallySigned structure from [RFC5246] section 4.7
#[derive(PartialEq)]
pub struct DigitallySigned<'a> {
    pub alg: Option<SignatureAndHashAlgorithm>,
    // pub alg: Option<u16>, // SignatureScheme
    pub data: &'a[u8],
}






named!(pub parse_digitally_signed_old<DigitallySigned>,
    map!(
        length_data!(be_u16),
        |d| { DigitallySigned{ alg:None, data:d } }
    )
);

named!(pub parse_digitally_signed<DigitallySigned>,
    do_parse!(
        h: be_u8 >>
        s: be_u8 >>
        d: length_data!(be_u16) >>
        ( DigitallySigned{
            alg: Some( SignatureAndHashAlgorithm{ hash:HashAlgorithm(h), sign:SignAlgorithm(s) } ),
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
