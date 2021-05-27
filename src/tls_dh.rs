use crate::utils::*;
use nom::IResult;
use nom_derive::Nom;
use std::borrow::Cow;

/// Diffie-Hellman parameters, defined in [RFC5246] section 7.4.3
#[derive(PartialEq, Nom)]
pub struct ServerDHParams<'a> {
    /// The prime modulus used for the Diffie-Hellman operation.
    #[nom(Parse = "length_data_cow_u16")]
    pub dh_p: Cow<'a, [u8]>,
    /// The generator used for the Diffie-Hellman operation.
    #[nom(Parse = "length_data_cow_u16")]
    pub dh_g: Cow<'a, [u8]>,
    /// The server's Diffie-Hellman public value (g^X mod p).
    #[nom(Parse = "length_data_cow_u16")]
    pub dh_ys: Cow<'a, [u8]>,
}

#[inline]
pub fn parse_dh_params(i: &[u8]) -> IResult<&[u8], ServerDHParams> {
    ServerDHParams::parse(i)
}
