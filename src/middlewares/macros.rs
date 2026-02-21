#[macro_export]
macro_rules! extract_service_response {
    ($req:expr, $expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                let (req, _) = $req.into_parts();
                return Ok(ServiceResponse::new(req, e.error_response()));
            }
        }
    };
}
