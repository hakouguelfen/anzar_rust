use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
#[derive(Serialize)]
pub enum Role {
    User,
    _Admin,
}
#[derive(Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: Role,
    #[serde(rename = "isPremium")]
    pub is_premium: bool,
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

    pub fn login_data() -> LoginRequest {
        LoginRequest {
            email: "hakouguelfen@gmail.com".into(),
            password: "hakouguelfen".into(),
        }
    }

    pub fn register_data() -> RegisterRequest {
        RegisterRequest {
            username: "hakouguelfen".into(),
            email: "hakouguelfen@gmail.com".into(),
            password: "hakouguelfen".into(),
            role: Role::User,
            is_premium: false,
        }
    }
}
