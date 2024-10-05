use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub struct TestCases;
impl TestCases {
    pub fn data() -> Vec<(LoginRequest, String)> {
        vec![
            (
                LoginRequest {
                    email: "hakouguelfen@gmail.com".into(),
                    password: "hakou".into(),
                },
                "password is wrong".into(),
            ),
            (
                LoginRequest {
                    email: "hakou@gmail.com".into(),
                    password: "hakouguelfen".into(),
                },
                "email is wrong".into(),
            ),
            (
                LoginRequest {
                    email: "".into(),
                    password: "hakouguelfen".into(),
                },
                "email is missing".into(),
            ),
            (
                LoginRequest {
                    email: "hakouguelfen@gmail.com".into(),
                    password: "".into(),
                },
                "password is missing".into(),
            ),
            (
                LoginRequest {
                    email: "".into(),
                    password: "".into(),
                },
                "both is missing".into(),
            ),
        ]
    }
}
