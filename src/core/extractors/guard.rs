// use actix_web::{
//     guard::{Guard, GuardContext},
//     http::header,
// };

// pub struct AdminGuard;
// impl Guard for AdminGuard {
//     fn check(&self, req: &GuardContext) -> bool {
//         let token: String = req
//             .head()
//             .headers()
//             .get(header::AUTHORIZATION)
//             .and_then(|v| v.to_str().ok())
//             .and_then(|v| v.strip_prefix("Bearer ").map(String::from))
//             .unwrap_or_default();

//         match jwt::decode_tokens(&token) {
//             Ok(acc_t) => acc_t.claims.role == Role::Admin,
//             Err(_) => false,
//         }
//     }
// }
