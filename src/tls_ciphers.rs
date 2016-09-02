#![allow(non_camel_case_types)]

#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum TlsCipherSuite {
    TLS_NULL_WITH_NULL_NULL = 0x0000,
    TLS_RSA_WITH_NULL_MD5 = 0x0001,
    TLS_RSA_WITH_NULL_SHA = 0x0002,








    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,



    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
}

// impl fmt::Display for TlsCipherSuite {
//     fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
//         let s : TlsAlertSeverity = self.severity.into();
//         let d : TlsAlertDescription = self.code.into();
//         write!(out, "TlsAlert(severity={:?},code={:?})", s, d)
//     }
// }
// 
// impl fmt::Debug for TlsCipherSuite {
//     fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
//         fmt::Display::fmt(self,out)
//     }
// }

// XXX write a derive function for that ?
impl From<u16> for TlsCipherSuite {
    fn from(t:u16) -> TlsCipherSuite {
        match t {
            0x0000 => TlsCipherSuite::TLS_NULL_WITH_NULL_NULL,
            0x0001 => TlsCipherSuite::TLS_RSA_WITH_NULL_MD5,
            0x0002 => TlsCipherSuite::TLS_RSA_WITH_NULL_SHA,


            0xc02f => TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            0xc030 => TlsCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

            0xcca8 => TlsCipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            _    => panic!("boo"),
        }
    }
}

// // unstable channel :(
// #[derive(Debug)]
// pub enum CastError {
//     InvalidValue(u16),
// }
// 
// use std::convert::TryFrom;
// 
// impl TryFrom<u16> for TlsCipherSuite {
//     type Err = CastError;
//     fn try_from(original: u16) -> Result<Self, Self::Err> {
//         match original {
//             0x0000 => Ok(TlsCipherSuite::TLS_NULL_WITH_NULL_NULL),
//             n      => Err(CastError::InvalidValue(n))
//         }
//     }
// }

