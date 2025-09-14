#![allow(dead_code)]
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EmailRequest {
    pub email: String,
}

#[derive(Serialize)]
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
    #[serde(rename = "accountLocked")]
    pub account_locked: bool,
}

pub struct ValidTestCases;
impl ValidTestCases {
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
            account_locked: false,
        }
    }
    pub fn register_data2() -> RegisterRequest {
        RegisterRequest {
            username: "hakouguelfen2".into(),
            email: "hakouguelfe2n@gmail.com".into(),
            password: "hakouguelfen2".into(),
            role: Role::User,
            is_premium: false,
            account_locked: false,
        }
    }
    pub fn blocked_account() -> RegisterRequest {
        RegisterRequest {
            username: "accountLocked".into(),
            email: "hakouguelfen@gmail.com".into(),
            password: "hakouguelfen".into(),
            role: Role::User,
            is_premium: false,
            account_locked: true,
        }
    }
}

pub struct InvalidTestCases;
impl InvalidTestCases {
    pub fn login_credentials() -> Vec<(LoginRequest, String, u16)> {
        vec![
            (
                LoginRequest {
                    email: "hakouguelfen@gmail.com".into(),
                    password: "hakouismyname".into(),
                },
                "password is wrong".into(),
                401,
            ),
            (
                LoginRequest {
                    email: "hakou@gmail.com".into(),
                    password: "hakouguelfen".into(),
                },
                "email is wrong".into(),
                401,
            ),
            (
                LoginRequest {
                    email: "".into(),
                    password: "hakouguelfen".into(),
                },
                "email is missing".into(),
                400,
            ),
            (
                LoginRequest {
                    email: "hakouguelfen@gmail.com".into(),
                    password: "".into(),
                },
                "password is missing".into(),
                400,
            ),
            (
                LoginRequest {
                    email: "".into(),
                    password: "".into(),
                },
                "both is missing".into(),
                400,
            ),
        ]
    }

    pub fn registration_credentials() -> Vec<(RegisterRequest, String, u16)> {
        vec![
            (
                RegisterRequest {
                    username: "hakouguelfen".into(),
                    email: "".into(),
                    password: "hakouguelfen".into(),
                    role: Role::User,
                    is_premium: false,
                    account_locked: false,
                },
                "missing email field".into(),
                400,
            ),
            (
                RegisterRequest {
                    username: "hakouguelfen".into(),
                    email: "hakouguelfen@gmail.com".into(),
                    password: "".into(),
                    role: Role::User,
                    is_premium: false,
                    account_locked: false,
                },
                "missing password field".into(),
                400,
            ),
            (
                RegisterRequest {
                    username: "email duplicate".into(),
                    email: "hakouguelfen@gmail.com".into(),
                    password: "hakouguelfen".into(),
                    role: Role::User,
                    is_premium: false,
                    account_locked: false,
                },
                "duplication emails".into(),
                401,
            ),
        ]
    }

    pub fn jwt_tokens(valid_token: String) -> Vec<(String, &'static str, u16)> {
        vec![
            (
                "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2ODliNjVmNDFlOWI2MTRiZWVkMTE4ZTQiLCJleHAiOjE3NTUwMTU1NDQsImlhdCI6MTc1NTAxNDY0NCwidG9rZW5fdHlwZSI6IkFjY2Vzc1Rva2VuIiwicm9sZSI6IlVzZXIifQ.fGAj4Q_yydKIbhZg_Aq9tvfQjBF_BP0BYUWioV1UlPQ".to_string(),
                "token is wrong",
                401,
            ),
            (
                "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ.eyJzdWIiOiI2ODliNjVmNDFlOWI2MTRiZWVkMTE4ZTQiLCJleHAiOjE3NTUwMTU1NDQsImlhdCI6MTc1NTAxNDY0NCwidG9rZW5fdHlwZSI6IkFjY2Vzc1Rva2VuIiwicm9sZSI6IlVzZXIif.fGAj4Q_yydKIbhZg_Aq9tvfQjBF_BP0BYUWioV1UlP".to_string(),
                "token is expired",
                401,
            ),
            (String::default(), "token is empty", 401),
            (valid_token, "token without Bearer keyword", 401),
        ]
    }

    pub fn refresh_tokens(valid_token: String) -> Vec<(String, &'static str, u16)> {
        vec![
            (
                format!("Bearer {valid_token}").to_string(),
                "token is valid with accountLocked",
                403
            ),
            (
                "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2ODliZDhiZWIzZTg4MDdiMzI4OGNkMjYiLCJleHAiOjE3NTYzNDAwMzEsImlhdCI6MTc1NTA0NDAzMSwianRpIjoiMTdiYjYxYWItNTVkZC00MTRjLWE4NGItZGQxMzkyZjYwYzM5IiwidG9rZW5fdHlwZSI6IlJlZnJlc2hUb2tlbiJ9.zSmSyDjVmD6DZuF2Li6-fY3osco2rYfS1Ai9fYZ3j-k".to_string(),
                "token is wrong",
                401
            ),
            (
                "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2ODliZDhiZWIzZTg4MDdiMzI4OGNkMjYiLCJleHAiOjE3NTUwNDQxMTcsImlhdCI6MTc1NTA0NDAzMSwianRpIjoiMTdiYjYxYWItNTVkZC00MTRjLWE4NGItZGQxMzkyZjYwYzM5IiwidG9rZW5fdHlwZSI6IlJlZnJlc2hUb2tlbiJ9.4na41dq0_11Gvx-1RcAVv6nCD7O5NZkkAYI6V3i70e4".to_string(),
                "token is expired",
                401
            ),
            (String::default(), "token is empty", 401),
            (valid_token, "token without Bearer keyword", 401),
        ]
    }
}
