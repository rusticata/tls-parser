use nom::multi::length_data;
use nom::number::streaming::be_u16;
use nom::IResult;
use nom_derive::*;

/// Diffie-Hellman parameters, defined in [RFC5246] section 7.4.3
#[derive(PartialEq, NomBE)]
pub struct ServerDHParams<'a> {
    /// The prime modulus used for the Diffie-Hellman operation.
    #[nom(Parse = "length_data(be_u16)")]
    pub dh_p: &'a [u8],
    /// The generator used for the Diffie-Hellman operation.
    #[nom(Parse = "length_data(be_u16)")]
    pub dh_g: &'a [u8],
    /// The server's Diffie-Hellman public value (g^X mod p).
    #[nom(Parse = "length_data(be_u16)")]
    pub dh_ys: &'a [u8],
}

#[inline]
pub fn parse_dh_params(i: &[u8]) -> IResult<&[u8], ServerDHParams> {
    ServerDHParams::parse(i)
}
