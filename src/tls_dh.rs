use nom::number::streaming::be_u16;

/// Diffie-Hellman parameters, defined in [RFC5246] section 7.4.3
#[derive(PartialEq)]
pub struct ServerDHParams<'a> {
    /// The prime modulus used for the Diffie-Hellman operation.
    pub dh_p: &'a [u8],
    /// The generator used for the Diffie-Hellman operation.
    pub dh_g: &'a [u8],
    /// The server's Diffie-Hellman public value (g^X mod p).
    pub dh_ys: &'a [u8],
}

named! {pub parse_dh_params<ServerDHParams>,
    do_parse!(
        p:  length_data!(be_u16) >>
        g:  length_data!(be_u16) >>
        ys: length_data!(be_u16) >>
        ( ServerDHParams{
            dh_p:  p,
            dh_g:  g,
            dh_ys: ys,
        })
    )
}
