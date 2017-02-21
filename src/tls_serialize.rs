#[cfg(feature = "serialize")]
pub mod serialize {

use tls::*;
use tls_extensions::TlsExtension;
use rusticata_macros::*;

pub fn gen_tls_extension<'a,'b>(x:(&'a mut [u8],usize),m:&'b TlsExtension) -> Result<(&'a mut [u8],usize),GenError> {
    match m {
        _ => Err(GenError::NotYetImplemented),
    }
}

pub fn gen_tls_sessionid<'a,'b>(x:(&'a mut [u8],usize),m:&Option<&'b [u8]>) -> Result<(&'a mut [u8],usize),GenError> {
    match m {
        &None    => gen_be_u8!(x,0),
        &Some(o) => {
            do_gen!(
                x,
                gen_be_u8!(o.len() as u8) >>
                gen_slice!(o)
            )
        }
    }
}

pub fn gen_tls_hellorequest<'a>(x:(&'a mut [u8],usize)) -> Result<(&'a mut [u8],usize),GenError> {
    do_gen!(
        x,
        gen_be_u8!(TlsHandshakeType::HelloRequest as u8) >>
        gen_be_u24!(0)
    )
}

pub fn gen_tls_clienthello<'a,'b>(x:(&'a mut [u8],usize),m:&'b TlsClientHelloContents) -> Result<(&'a mut [u8],usize),GenError> {
    do_gen!(
        x,
                 gen_be_u8!(TlsHandshakeType::ClientHello as u8) >>
        ofs_len: gen_skip!(3) >>
        start:   gen_be_u16!(m.version) >>
                 gen_be_u32!(m.rand_time) >>
                 gen_copy!(m.rand_data,28) >>
                 gen_tls_sessionid(&m.session_id) >>
                 gen_be_u16!((m.ciphers.len()*2) as u16) >>
                 gen_many!(m.ciphers,set_be_u16) >>
                 gen_be_u8!(m.comp.len() as u8) >>
                 gen_many!(m.comp,set_be_u8) >>
                 gen_cond!(m.ext.is_some(),gen_slice!(m.ext.unwrap())) >>
        end:     gen_at_offset!(ofs_len,gen_be_u24!(end-start))
    )
}

pub fn gen_tls_messagehandshake<'a,'b>(x:(&'a mut [u8],usize),m:&'b TlsMessageHandshake) -> Result<(&'a mut [u8],usize),GenError> {
    match m {
        &TlsMessageHandshake::HelloRequest => gen_tls_hellorequest(x),
        &TlsMessageHandshake::ClientHello(ref m) => gen_tls_clienthello(x,m),
        _ => Err(GenError::NotYetImplemented),
    }
}

pub fn gen_tls_message<'a,'b>(x:(&'a mut [u8],usize),m:&'b TlsMessage) -> Result<(&'a mut [u8],usize),GenError> {
    match m {
        &TlsMessage::Handshake(ref m) => gen_tls_messagehandshake(x,m),
        _ => Err(GenError::NotYetImplemented),
    }
}

/// Write a TlsPlaintext record to the input slice
///
/// if p.hdr.len is 0, compute the real size of the record
/// otherwise, use the provided length
pub fn gen_tls_plaintext<'a,'b>(x:(&'a mut [u8],usize),p:&'b TlsPlaintext) -> Result<(&'a mut [u8],usize),GenError> {
    do_gen!(
        x,
                 gen_be_u8!(p.hdr.record_type) >>
                 gen_be_u16!(p.hdr.version) >>
        ofs_len: gen_be_u16!(p.hdr.len) >>
        // gen_skip!(2) >>
        start:   gen_many_ref!(&p.msg,gen_tls_message) >>
        end:     gen_cond!(p.hdr.len == 0,
                           gen_at_offset!(ofs_len,gen_be_u16!(end-start)))
    )
}


#[cfg(test)]
mod tests {
    use super::*;
    use nom::IResult;

    #[test]
    fn serialize_clienthello() {
        let rand_data = [0xff, 0x21, 0xeb, 0x04, 0xc8, 0xa5, 0x38, 0x39, 0x9a,
        0xcf, 0xb7, 0xa3, 0x82, 0x1f, 0x82, 0x6c, 0x49, 0xbc, 0x8b, 0xb8, 0xa9,
        0x03, 0x0a, 0x2d, 0xce, 0x38, 0x0b, 0xf4];
        let ciphers = vec![
            0xc030,
            0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x00a5,
            0x00a3, 0x00a1, 0x009f, 0x006b, 0x006a, 0x0069,
            0x0068, 0x0039, 0x0038, 0x0037, 0x0036, 0x0088,
            0x0087, 0x0086, 0x0085, 0xc032, 0xc02e, 0xc02a,
            0xc026, 0xc00f, 0xc005, 0x009d, 0x003d, 0x0035,
            0x0084, 0xc02f, 0xc02b, 0xc027, 0xc023, 0xc013,
            0xc009, 0x00a4, 0x00a2, 0x00a0, 0x009e, 0x0067,
            0x0040, 0x003f, 0x003e, 0x0033, 0x0032, 0x0031,
            0x0030, 0x009a, 0x0099, 0x0098, 0x0097, 0x0045,
            0x0044, 0x0043, 0x0042, 0xc031, 0xc02d, 0xc029,
            0xc025, 0xc00e, 0xc004, 0x009c, 0x003c, 0x002f,
            0x0096, 0x0041, 0xc011, 0xc007, 0xc00c, 0xc002,
            0x0005, 0x0004, 0xc012, 0xc008, 0x0016, 0x0013,
            0x0010, 0x000d, 0xc00d, 0xc003, 0x000a, 0x00ff
        ];
        let comp = vec![0x00];

        let expected = TlsPlaintext {
            hdr: TlsRecordHeader {
                record_type: TlsRecordType::Handshake as u8,
                version: 0x0301,
                len: 213,
            },
            msg: vec![TlsMessage::Handshake(
                     TlsMessageHandshake::ClientHello(
                         TlsClientHelloContents {
                             version: 0x0303,
                             rand_time: 0xb29dd787,
                             rand_data: &rand_data,
                             session_id: None,
                             ciphers: ciphers,
                             comp: comp,
                             ext: None,
                         })
                     )]
        };

        {
            let mut mem : [u8; 218] = [0; 218];
            let s = &mut mem[..];

            let res = gen_tls_plaintext((s,0), &expected);
            println!("res: {:?}", res);
            match res {
                Ok((b,_)) => {
                    let res_reparse = parse_tls_plaintext(b);
                    assert_eq!(res_reparse,IResult::Done(&b""[..],expected));
                },
                Err(e)    => println!("Error: {:?}",e),
            };

        }

    }
}

}
