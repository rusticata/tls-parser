use tls::*;

pub enum StateChangeError {
    InvalidTransition,
    ParseError,
}

#[derive(Copy,Clone,Debug,PartialEq)]
pub enum TlsState {
    None,
    ClientHello,
    AskResumeSession,
    ResumeSession,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    ServerHelloDone,
    ClientKeyExchange,
    ClientChangeCipherSpec,

    CRCertRequest,
    CRHelloDone,
    CRCert,
    CRClientKeyExchange,
    CRCertVerify,

    NoCertSKE,
    NoCertHelloDone,
    NoCertCKE,

    SessionEncrypted,

    Alert,

    Invalid,
}

pub fn tls_state_transition_handshake(state: TlsState, msg: &TlsMessageHandshake) -> Result<TlsState,StateChangeError> {
    match (state,msg) {
        (TlsState::None,             &TlsMessageHandshake::ClientHello(ref msg)) => {
            match msg.session_id {
                Some(_) => Ok(TlsState::AskResumeSession),
                _       => Ok(TlsState::ClientHello)
            }
        },
        // Server certificate
        (TlsState::ClientHello,      &TlsMessageHandshake::ServerHello(_))       => Ok(TlsState::ServerHello),
        (TlsState::ServerHello,      &TlsMessageHandshake::Certificate(_))       => Ok(TlsState::Certificate),
        // Server certificate, no client certificate requested
        (TlsState::Certificate,      &TlsMessageHandshake::ServerKeyExchange(_)) => Ok(TlsState::ServerKeyExchange),
        (TlsState::ServerKeyExchange,&TlsMessageHandshake::ServerDone(_))        => Ok(TlsState::ServerHelloDone),
        (TlsState::ServerHelloDone  ,&TlsMessageHandshake::ClientKeyExchange(_)) => Ok(TlsState::ClientKeyExchange),
        // Server certificate, client certificate requested
        (TlsState::Certificate,      &TlsMessageHandshake::CertificateRequest(_))=> Ok(TlsState::CRCertRequest),
        (TlsState::ServerKeyExchange,&TlsMessageHandshake::CertificateRequest(_))=> Ok(TlsState::CRCertRequest),
        (TlsState::CRCertRequest,    &TlsMessageHandshake::ServerDone(_))        => Ok(TlsState::CRHelloDone),
        (TlsState::CRHelloDone,      &TlsMessageHandshake::Certificate(_))       => Ok(TlsState::CRCert),
        (TlsState::CRCert,           &TlsMessageHandshake::ClientKeyExchange(_)) => Ok(TlsState::CRClientKeyExchange),
        (TlsState::CRClientKeyExchange, &TlsMessageHandshake::CertificateVerify(_)) => Ok(TlsState::CRCertVerify),
        // Server has no certificate (but accepts anonymous)
        (TlsState::ServerHello,      &TlsMessageHandshake::ServerKeyExchange(_)) => Ok(TlsState::NoCertSKE),
        (TlsState::NoCertSKE,        &TlsMessageHandshake::ServerDone(_))        => Ok(TlsState::NoCertHelloDone),
        (TlsState::NoCertHelloDone,  &TlsMessageHandshake::ClientKeyExchange(_)) => Ok(TlsState::NoCertCKE),
        // Resuming session
        (TlsState::AskResumeSession, &TlsMessageHandshake::ServerHello(_))       => Ok(TlsState::ResumeSession),
        // Hello requests must be accepted at any time (except start), but ignored [RFC5246] 7.4.1.1
        (TlsState::None,             &TlsMessageHandshake::HelloRequest)         => Err(StateChangeError::InvalidTransition),
        (s,                          &TlsMessageHandshake::HelloRequest)         => Ok(s),
        // All other transitions are considered invalid
        _ => Err(StateChangeError::InvalidTransition),
    }
}

pub fn tls_state_transition(state: TlsState, msg: &TlsMessage) -> Result<TlsState,StateChangeError> {
    match (state,msg) {
        (TlsState::Invalid,_) => Ok(TlsState::Invalid),
        (_,&TlsMessage::Handshake(ref m)) => tls_state_transition_handshake(state,m),
        // Server certificate
        (TlsState::ClientKeyExchange,     &TlsMessage::ChangeCipherSpec) => Ok(TlsState::ClientChangeCipherSpec),
        (TlsState::ClientChangeCipherSpec,&TlsMessage::ChangeCipherSpec) => Ok(TlsState::SessionEncrypted),
        // Server certificate, client certificate requested
        (TlsState::CRClientKeyExchange,   &TlsMessage::ChangeCipherSpec) => Ok(TlsState::ClientChangeCipherSpec),
        (TlsState::CRCertVerify,          &TlsMessage::ChangeCipherSpec) => Ok(TlsState::ClientChangeCipherSpec),
        // No server certificate
        (TlsState::NoCertCKE,             &TlsMessage::ChangeCipherSpec) => Ok(TlsState::ClientChangeCipherSpec),
        // Resume session
        (TlsState::ResumeSession,         &TlsMessage::ChangeCipherSpec) => Ok(TlsState::ClientChangeCipherSpec),
        (_,_) => Err(StateChangeError::InvalidTransition),
    }
}
