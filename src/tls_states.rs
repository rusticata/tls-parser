use tls::*;

/// Error types for the state machine
pub enum StateChangeError {
    InvalidTransition,
    ParseError,
}

/// TLS machine possible states
#[derive(Copy,Clone,Debug,PartialEq)]
pub enum TlsState {
    None,
    ClientHello,
    AskResumeSession,
    ResumeSession,
    ServerHello,
    Certificate,
    CertificateSt,
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

    PskHelloDone,
    PskCKE,

    SessionEncrypted,

    Alert,

    Invalid,
}

fn tls_state_transition_handshake(state: TlsState, msg: &TlsMessageHandshake) -> Result<TlsState,StateChangeError> {
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
        (TlsState::Certificate,      &TlsMessageHandshake::CertificateStatus(_)) => Ok(TlsState::CertificateSt),
        (TlsState::CertificateSt,    &TlsMessageHandshake::ServerKeyExchange(_)) => Ok(TlsState::ServerKeyExchange),
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
        // PSK
        (TlsState::Certificate,      &TlsMessageHandshake::ServerDone(_))        => Ok(TlsState::PskHelloDone),
        (TlsState::PskHelloDone,     &TlsMessageHandshake::ClientKeyExchange(_)) => Ok(TlsState::PskCKE),
        // Resuming session
        (TlsState::AskResumeSession, &TlsMessageHandshake::ServerHello(_))       => Ok(TlsState::ResumeSession),
        // TLS 1.3 Draft 18 1-RTT
        // Re-use the ClientChangeCipherSpec state to indicate the next message will be encrypted
        (TlsState::ClientHello,      &TlsMessageHandshake::ServerHelloV13Draft18(_))    => Ok(TlsState::ClientChangeCipherSpec),
        // Hello requests must be accepted at any time (except start), but ignored [RFC5246] 7.4.1.1
        (TlsState::None,             &TlsMessageHandshake::HelloRequest)         => Err(StateChangeError::InvalidTransition),
        (s,                          &TlsMessageHandshake::HelloRequest)         => Ok(s),
        // All other transitions are considered invalid
        _ => Err(StateChangeError::InvalidTransition),
    }
}

/// Update the TLS state machine, doing one transition
///
/// Given the previous state and the parsed message, return the new state or a state machine error.
///
/// This state machine only implements the TLS handshake.
///
/// Some transitions only check the new message type, while some others must match the content
/// (for example, to check if the client asked to resume a session).
///
/// If the previous state is `Invalid`, the state machine will not return an error, but keep the
/// same `Invalid` state. This is used to raise error only once if the state machine keeps being
/// updated by new messages.
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
        // PSK
        (TlsState::PskCKE,                &TlsMessage::ChangeCipherSpec) => Ok(TlsState::ClientChangeCipherSpec),
        // Resume session
        (TlsState::ResumeSession,         &TlsMessage::ChangeCipherSpec) => Ok(TlsState::ClientChangeCipherSpec),
        (_,_) => Err(StateChangeError::InvalidTransition),
    }
}
