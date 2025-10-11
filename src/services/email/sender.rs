use resend_rs::{Resend, types::CreateEmailBaseOptions};

use crate::error::{Error, Result};

pub struct Email {
    reciever: String,
    mail: Resend,
}

impl Default for Email {
    fn default() -> Self {
        Self::new()
    }
}

impl Email {
    pub fn new() -> Self {
        Self {
            reciever: String::default(),
            mail: Resend::new("re_dYG1K7jD_BUB6VjtLGXne1ezrjdRvQTwM"),
        }
    }
    pub fn to(mut self, reciever: impl Into<String>) -> Self {
        self.reciever = reciever.into();
        self
    }

    pub async fn send(self, username: &str, token: &str) -> Result<String> {
        let subject = "Password Reseting";
        let from = "onboarding@resend.dev";

        let reset_link = format!("http://localhost:3000/auth/password/reset?token={}", &token);
        let body = format!(
            include_str!("../../services/email/templates/password_reset.html"),
            username, &reset_link, &reset_link
        );

        let email = CreateEmailBaseOptions::new(from, [&self.reciever], subject).with_html(&body);

        self.mail.emails.send(email).await.map_err(|e| {
            tracing::error!("Failed to send password reset email: {:?}", e);
            Error::EmailSendFailed { to: self.reciever }
        })?;

        Ok("Email sent successfully!".to_string())
    }
}
