use crate::utils::HmacSigner;

pub struct LoginAttemptTracker<'a> {
    signer: &'a HmacSigner,
}

impl<'a> LoginAttemptTracker<'a> {
    pub fn new(signer: &'a HmacSigner) -> Self {
        Self { signer }
    }

    pub fn resolve_identity(&self, cookie: Option<&str>, email: &str) -> String {
        // "who is making attempts" — device identity takes priority if verified
        match cookie {
            Some(val) => format!("device:{}", val),
            None => format!("user:{}", email),
        }
    }

    pub fn resolve_lockout_key(&self, cookie: Option<&str>, email: &str) -> String {
        // "what gets locked out" — verified device vs user account
        match cookie.and_then(|c| self.signer.validate(c)) {
            Some(true) => format!("lockout:device:{}", cookie.unwrap()),
            Some(false) | None => format!("lockout:user:{}", email),
        }
    }
}
