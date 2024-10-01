use crate::scopes::auth::Result;

#[derive(Default)]
pub struct Email {
    sender: String,
    reciever: String,
}
impl Email {
    pub fn new() -> Self {
        Email::default()
    }
    pub fn with_sender(mut self, sender: impl Into<String>) -> Self {
        self.sender = sender.into();
        self
    }
    pub fn with_reciever(mut self, reciever: impl Into<String>) -> Self {
        self.reciever = reciever.into();
        self
    }

    pub fn send(self) -> Result<String> {
        // let email = Message::builder()
        //     .from(self.sender.parse().unwrap())
        //     .to(self.reciever.parse().unwrap())
        //     .subject("Happy new year")
        //     .body("Be happy!".to_string())
        //     .unwrap();

        // // Replace with your actual Gmail credentials
        // let creds = Credentials::new(
        //     "hakouklvn79@gmail.com".to_string(),
        //     "death and life 1123581321".to_string(),
        // );

        // // Configure the mailer with Gmail's SMTP server
        // let mailer = SmtpTransport::relay("smtp.gmail.com")
        //     .unwrap()
        //     .credentials(creds)
        //     .build();

        // // Send the email
        // match mailer.send(&email) {
        //     Ok(_) => Ok("Email sent successfully!".to_string()),
        //     Err(_) => Err(Error::InternalError),
        // }

        Ok("Email sent successfully!".to_string())
    }
}
