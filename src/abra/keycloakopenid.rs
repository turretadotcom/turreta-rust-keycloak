#![crate_name = "doc"]

use reqwest::header::{HeaderValue, CONTENT_TYPE, ACCEPT};
use crate::abra::urls;
use crate::abra::urls::{OpenIdConnectURIs};

/// Struct that represents the token response from Keycloak
#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub expires_in: i32,
    pub refresh_expires_in: i32,
    pub refresh_token: String,
    pub token_type: String,
    pub session_state: String,
    // pub scope: String,
}

pub async fn get_token(path: &str, payload: serde_json::Value) -> Result<Token, reqwest::Error> {

    let client = reqwest::Client::new();
    let k_res = client
        .post(path)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"))
        .form(&payload)
        .send()
        .await?.error_for_status()?;
    k_res.json().await
}

pub async fn introspect_token(
    path: &str,
    payload: serde_json::Value,
) -> Result<String, reqwest::Error> {
    let client = reqwest::Client::new();
    let k_res = client
        .post(path)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .form(&payload)
        .send()
        .await?.error_for_status()?;
    k_res.text().await
}
