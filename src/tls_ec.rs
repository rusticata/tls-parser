use nom::{be_u8,be_u16};
use enum_primitive::FromPrimitive;

enum_from_primitive! {
/// Named curves, as defined in [RFC4492](https://tools.ietf.org/html/rfc4492), [RFC7027](https://tools.ietf.org/html/rfc7027), [RFC7919](https://tools.ietf.org/html/rfc7919) and
/// [IANA Supported Groups
/// Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum NamedCurve {
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

impl NamedCurve {
    /// Return key size of curve in bits, or None if unknown
    pub fn key_bits(self: &NamedCurve) -> Option<u16> {
        match *self {
            NamedCurve::Sect163k1 => Some(163),
            NamedCurve::Sect163r1 => Some(163),
            NamedCurve::Sect163r2 => Some(163),
            NamedCurve::Sect193r1 => Some(193),
            NamedCurve::Sect193r2 => Some(193),
            NamedCurve::Sect233k1 => Some(233),
            NamedCurve::Sect233r1 => Some(233),
            NamedCurve::Sect239k1 => Some(239),
            NamedCurve::Sect283k1 => Some(283),
            NamedCurve::Sect283r1 => Some(283),
            NamedCurve::Sect409k1 => Some(409),
            NamedCurve::Sect409r1 => Some(409),
            NamedCurve::Sect571k1 => Some(571),
            NamedCurve::Sect571r1 => Some(571),
            NamedCurve::Secp160k1 => Some(160),
            NamedCurve::Secp160r1 => Some(160),
            NamedCurve::Secp160r2 => Some(160),
            NamedCurve::Secp192k1 => Some(192),
            NamedCurve::Secp192r1 => Some(192),
            NamedCurve::Secp224k1 => Some(224),
            NamedCurve::Secp224r1 => Some(224),
            NamedCurve::Secp256k1 => Some(256),
            NamedCurve::Secp256r1 => Some(256),
            NamedCurve::Secp384r1 => Some(384),
            NamedCurve::Secp521r1 => Some(521),
            NamedCurve::BrainpoolP256r1 => Some(256),
            NamedCurve::BrainpoolP384r1 => Some(384),
            NamedCurve::BrainpoolP512r1 => Some(521),
            NamedCurve::EcdhX25519 => Some(253),
            _                     => None,
        }
    }
}

pub fn named_curve_of_u16(id: u16) -> Option<NamedCurve> {
    NamedCurve::from_u16(id)
}

#[derive(Debug,PartialEq)]
pub struct ECCurve<'a> {
    pub a: &'a[u8],
    pub b: &'a[u8],
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum ECCurveType {
    ExplicitPrime = 1,
    ExplicitChar2 = 2,
    NamedCurve = 3,
}
}

#[derive(Debug,PartialEq)]
pub struct ECPoint<'a> {
    pub point: &'a[u8],
}

#[derive(Debug,PartialEq)]
pub struct ExplicitPrimeContent<'a> {
    pub prime_p: &'a[u8],
    pub curve: ECCurve<'a>,
    pub base: ECPoint<'a>,
    pub order: &'a[u8],
    pub cofactor: &'a[u8],
}


#[derive(Debug,PartialEq)]
pub enum ECParametersContent<'a> {
    ExplicitPrime(ExplicitPrimeContent<'a>),
    // TODO ExplicitChar2 is defined in [RFC4492] section 5.4
    ExplicitChar2(&'a[u8]),
    NamedCurve(u16),
}

#[derive(Debug,PartialEq)]
pub struct ECParameters<'a> {
    pub curve_type: u8,
    pub params_content: ECParametersContent<'a>,
}

#[derive(Debug,PartialEq)]
pub struct ServerECDHParams<'a> {
    pub curve_params: ECParameters<'a>,
    pub public: ECPoint<'a>,
}

named!(pub parse_ec_point<ECPoint>,
       map!(length_bytes!(be_u8),|d| { ECPoint{ point:d } })
);

named!(parse_ec_curve<ECCurve>,
    do_parse!(
        a: length_bytes!(be_u8) >>
        b: length_bytes!(be_u8) >>
        ( ECCurve{a:a,b:b} )
    )
);

named!(parse_ec_explicit_prime_content<ECParametersContent>,
    do_parse!(
        p:        length_bytes!(be_u8) >>
        curve:    parse_ec_curve >>
        base:     parse_ec_point >>
        order:    length_bytes!(be_u8) >>
        cofactor: length_bytes!(be_u8) >>
        (
            ECParametersContent::ExplicitPrime(
                ExplicitPrimeContent{
                    prime_p:  p,
                    curve:    curve,
                    base:     base,
                    order:    order,
                    cofactor: cofactor,
                }
            )
        )
    )
);

named!(parse_ec_named_curve_content<ECParametersContent>,
    map!(be_u16,|c|{ECParametersContent::NamedCurve(c)})
);

named!(pub parse_ec_parameters<ECParameters>,
    do_parse!(
        curve_type: be_u8  >>
        d: switch!(value!(curve_type),
            1 => call!(parse_ec_explicit_prime_content) |
            3 => call!(parse_ec_named_curve_content)
        ) >>
        (
            ECParameters{
                curve_type: curve_type,
                params_content: d,
            }
        )
    )
);

named!(pub parse_ecdh_params<ServerECDHParams>,
    do_parse!(
        c: parse_ec_parameters >>
        p: parse_ec_point >>
        ( ServerECDHParams{curve_params:c,public:p} )
    )
);
