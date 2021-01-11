use nom::error::ErrorKind;
use nom::number::streaming::{be_u16, be_u8};
use nom::{Err, IResult};

/// Named curves, as defined in [RFC4492](https://tools.ietf.org/html/rfc4492), [RFC7027](https://tools.ietf.org/html/rfc7027), [RFC7919](https://tools.ietf.org/html/rfc7919) and
/// [IANA Supported Groups
/// Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NamedGroup(pub u16);

newtype_enum! {
impl debug NamedGroup {
    Sect163k1 = 1,
    Sect163r1 = 2,
    Sect163r2 = 3,
    Sect193r1 = 4,
    Sect193r2 = 5,
    Sect233k1 = 6,
    Sect233r1 = 7,
    Sect239k1 = 8,
    Sect283k1 = 9,
    Sect283r1 = 10,
    Sect409k1 = 11,
    Sect409r1 = 12,
    Sect571k1 = 13,
    Sect571r1 = 14,
    Secp160k1 = 15,
    Secp160r1 = 16,
    Secp160r2 = 17,
    Secp192k1 = 18,
    Secp192r1 = 19,
    Secp224k1 = 20,
    Secp224r1 = 21,
    Secp256k1 = 22,
    Secp256r1 = 23,
    Secp384r1 = 24,
    Secp521r1 = 25,
    BrainpoolP256r1 = 26,
    BrainpoolP384r1 = 27,
    BrainpoolP512r1 = 28,
    EcdhX25519 = 29,
    EcdhX448 = 30,
    Ffdhe2048 = 0x100,
    Ffdhe3072 = 0x101,
    Ffdhe4096 = 0x102,
    Ffdhe6144 = 0x103,
    Ffdhe8192 = 0x104,
    ArbitraryExplicitPrimeCurves = 0xFF01,
    ArbitraryExplicitChar2Curves = 0xFF02,
}
}

impl NamedGroup {
    /// Return key size of curve in bits, or None if unknown
    pub fn key_bits(self: &NamedGroup) -> Option<u16> {
        match *self {
            NamedGroup::Sect163k1 => Some(163),
            NamedGroup::Sect163r1 => Some(163),
            NamedGroup::Sect163r2 => Some(163),
            NamedGroup::Sect193r1 => Some(193),
            NamedGroup::Sect193r2 => Some(193),
            NamedGroup::Sect233k1 => Some(233),
            NamedGroup::Sect233r1 => Some(233),
            NamedGroup::Sect239k1 => Some(239),
            NamedGroup::Sect283k1 => Some(283),
            NamedGroup::Sect283r1 => Some(283),
            NamedGroup::Sect409k1 => Some(409),
            NamedGroup::Sect409r1 => Some(409),
            NamedGroup::Sect571k1 => Some(571),
            NamedGroup::Sect571r1 => Some(571),
            NamedGroup::Secp160k1 => Some(160),
            NamedGroup::Secp160r1 => Some(160),
            NamedGroup::Secp160r2 => Some(160),
            NamedGroup::Secp192k1 => Some(192),
            NamedGroup::Secp192r1 => Some(192),
            NamedGroup::Secp224k1 => Some(224),
            NamedGroup::Secp224r1 => Some(224),
            NamedGroup::Secp256k1 => Some(256),
            NamedGroup::Secp256r1 => Some(256),
            NamedGroup::Secp384r1 => Some(384),
            NamedGroup::Secp521r1 => Some(521),
            NamedGroup::BrainpoolP256r1 => Some(256),
            NamedGroup::BrainpoolP384r1 => Some(384),
            NamedGroup::BrainpoolP512r1 => Some(521),
            NamedGroup::EcdhX25519 => Some(253),
            _ => None,
        }
    }
}

/// Elliptic curve
///
/// a and b specify the coefficients of the curve
#[derive(Debug, PartialEq)]
pub struct ECCurve<'a> {
    pub a: &'a [u8],
    pub b: &'a [u8],
}

/// Elliptic curve types, as defined in the
/// [IANA EC Curve Type Registry
/// Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ECCurveType(pub u8);

newtype_enum! {
impl display ECCurveType {
    ExplicitPrime = 1,
    ExplicitChar2 = 2,
    NamedGroup = 3,
}
}

/// EC Point
#[derive(Clone, Debug, PartialEq)]
pub struct ECPoint<'a> {
    pub point: &'a [u8],
}

/// Elliptic curve parameters, conveyed verbosely as a prime field, as
/// defined in [RFC4492](https://tools.ietf.org/html/rfc4492) section 5.4
#[derive(Debug, PartialEq)]
pub struct ExplicitPrimeContent<'a> {
    pub prime_p: &'a [u8],
    pub curve: ECCurve<'a>,
    pub base: ECPoint<'a>,
    pub order: &'a [u8],
    pub cofactor: &'a [u8],
}

/// Elliptic curve parameters content (depending on EC type)
#[derive(PartialEq)]
pub enum ECParametersContent<'a> {
    ExplicitPrime(ExplicitPrimeContent<'a>),
    // TODO ExplicitChar2 is defined in [RFC4492] section 5.4
    ExplicitChar2(&'a [u8]),
    NamedGroup(NamedGroup),
}

/// Elliptic curve parameters,
/// defined in [RFC4492](https://tools.ietf.org/html/rfc4492) section 5.4
#[derive(PartialEq)]
pub struct ECParameters<'a> {
    /// Should match a [ECCurveType](enum.ECCurveType.html) value
    pub curve_type: ECCurveType,
    pub params_content: ECParametersContent<'a>,
}

/// ECDH parameters
/// defined in [RFC4492](https://tools.ietf.org/html/rfc4492) section 5.4
#[derive(Debug, PartialEq)]
pub struct ServerECDHParams<'a> {
    pub curve_params: ECParameters<'a>,
    pub public: ECPoint<'a>,
}

/// Parse the entire input as a list of named groups (curves)
pub fn parse_named_groups(i: &[u8]) -> IResult<&[u8], Vec<NamedGroup>> {
    let len = i.len();
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
    }
    let v = (&i[..len])
        .chunks(2)
        .map(|chunk| NamedGroup((chunk[0] as u16) << 8 | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

named!(
    parse_ec_point<ECPoint>,
    map!(length_data!(be_u8), |d| { ECPoint { point: d } })
);

named! {parse_ec_curve<ECCurve>,
    do_parse!(
        a: length_data!(be_u8) >>
        b: length_data!(be_u8) >>
        ( ECCurve{a,b} )
    )
}

named! {parse_ec_explicit_prime_content<ECParametersContent>,
    do_parse!(
        p:        length_data!(be_u8) >>
        curve:    parse_ec_curve >>
        base:     parse_ec_point >>
        order:    length_data!(be_u8) >>
        cofactor: length_data!(be_u8) >>
        (
            ECParametersContent::ExplicitPrime(
                ExplicitPrimeContent{
                    prime_p:  p,
                    curve,
                    base,
                    order,
                    cofactor,
                }
            )
        )
    )
}

named!(
    parse_ec_named_curve_content<ECParametersContent>,
    map!(be_u16, |c| {
        ECParametersContent::NamedGroup(NamedGroup(c))
    })
);

named! {pub parse_ec_parameters<ECParameters>,
    do_parse!(
        curve_type: be_u8  >>
        d: switch!(value!(curve_type),
            1 => call!(parse_ec_explicit_prime_content) |
            3 => call!(parse_ec_named_curve_content)
        ) >>
        (
            ECParameters{
                curve_type: ECCurveType(curve_type),
                params_content: d,
            }
        )
    )
}

named! {pub parse_ecdh_params<ServerECDHParams>,
    do_parse!(
        c: parse_ec_parameters >>
        p: parse_ec_point >>
        ( ServerECDHParams{curve_params:c,public:p} )
    )
}
