pub enum Environment {
    Dev,
    Prod,
}
impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Dev => "dev",
            Environment::Prod => "prod",
        }
    }
    pub fn _is_dev(&self) -> bool {
        matches!(self, Environment::Dev)
    }
    pub fn _is_prod(&self) -> bool {
        matches!(self, Environment::Prod)
    }
}
impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "dev" => Ok(Self::Dev),
            "prod" => Ok(Self::Prod),
            other => Err(format!(
                "{} is not supported enironment. Use either `dev` or  `prod`",
                other
            )),
        }
    }
}
