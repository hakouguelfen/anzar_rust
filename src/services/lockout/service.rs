use crate::utils::HmacSigner;

pub struct LockoutService<'a> {
    signer: &'a HmacSigner,
}

impl<'a> LockoutService<'a> {
    pub fn new(signer: &'a HmacSigner) -> Self {
        Self { signer }
    }

    pub fn lockout_key(&self, cookie: Option<&str>, email: &str) -> String {
        match cookie.and_then(|c| self.signer.validate(c)) {
            Some(true) => format!("lockout:{}", cookie.unwrap()),
            Some(false) => format!("lockout:user:{}", email),
            None => format!("lockout:user:{}", email),
        }
    }

    pub fn attempts_key(&self, cookie: Option<&str>, email: &str) -> String {
        match cookie {
            Some(val) => val.into(),
            None => format!("user:{}", email),
        }
    }
}
