#[derive(Debug)]
pub enum IntToEnumError {
    InvalidU8(u8),
    InvalidU16(u16),
}

/// Named curves, as defined in [RFC4492], [RFC7027], [RFC7919]
enum_from_primitive! {
#[derive(Debug)]
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

/// Hash algorithms, as defined in [RFC5246]
enum_from_primitive! {
#[derive(Debug)]
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
#[derive(Debug)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    Anonymous = 0,
    Rsa = 1,
    Dsa = 2,
    Ecdsa = 3,
}
}


#[macro_export]
macro_rules! error_if (
  ($i:expr, $cond:expr, $err:expr) => (
    {
      if $cond {
        IResult::Error($err)
      } else {
        IResult::Done($i, ())
      }
    }
  );
  ($i:expr, $cond:expr, $err:expr) => (
    error!($i, $cond, $err);
  );
);



pub fn bytes_to_u64(s: &[u8]) -> Result<u64, &'static str> {
    let mut u = 0;

    for &c in s {
        u *= 256;
        u += c as u64;
    }

    Ok(u)
}

#[macro_use]
macro_rules! parse_hex_to_u64 (
    ( $i:expr, $size:expr ) => (
        map_res!($i, take!(($size as usize)), $crate::bytes_to_u64)
    );
);

#[macro_use]
named!(pub parse_uint24<&[u8], u64>, parse_hex_to_u64!(3));

//named!(parse_hex4<&[u8], u64>, parse_hex_to_u64!(4));
