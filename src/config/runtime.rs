pub enum Runtime {
    Docker,
    Local,
}

impl Runtime {
    pub fn as_str(&self) -> &'static str {
        match self {
            Runtime::Docker => "docker",
            Runtime::Local => "local",
        }
    }
    pub fn _is_docker(&self) -> bool {
        matches!(self, Runtime::Docker)
    }
}
impl std::fmt::Display for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for Runtime {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "docker" => Ok(Self::Docker),
            "local" => Ok(Self::Local),
            other => Err(format!(
                "{} is not supported runtime. Use either `docker` or  `local`",
                other
            )),
        }
    }
}
