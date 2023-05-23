use reqwest::header::{HeaderValue, CONTENT_TYPE};

use crate::abra::keycloak_commons::{
    KeycloakOpenIdConnectClientContext,
    OpenIdAuthenticateResponse,
    OpenIdIssuerResponse,
    OpenIdUserInfoResponse,
    ValidateTokenResponse
};

/// Keycloak Open ID Connect Service
pub struct KeycloakOpenIdConnectService();

impl KeycloakOpenIdConnectService {

    /// Retrieve available endpoints related to OpenID using the following Keycloak URL.
    ///
    /// E.g., http://{host}:{port}/auth/realms/{realm-name}/.well-known/openid-configuration
    ///
    pub async fn get_open_id_connect_endpoints(context: &KeycloakOpenIdConnectClientContext) -> Result<String, reqwest::Error> {
        let url = &context.open_id_connect_template_uris
            .openid_configuration_endpoint_uri
            .replace("{realm-name}", &context.realm_name);
        let client = reqwest::Client::new();

        let base_url = &context.keycloak_base_url;
        let path = base_url.clone() + &url.to_owned();
        let res = client.get(&path).send().await?;
        res.text().await
    }

    /// Retrieve issue details
    ///
    /// E.g., http://localhost:8080/auth/realms/turreta-alerts
    pub async fn get_issuer_details(context: &KeycloakOpenIdConnectClientContext) -> Result<OpenIdIssuerResponse, reqwest::Error> {
        let url = &context
            .open_id_connect_template_uris
            .issuer_endpoint_uri
            .replace("{realm-name}", &context.realm_name);
        let client = reqwest::Client::new();

        let base_url = &context.keycloak_base_url;
        let path = base_url.clone() + &url.to_owned();
        let res = client.get(&path).send().await?;
        res.json().await
    }

    /// Authenticate user that belong to a specific realm and client.
    ///
    /// E.g., http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token
    pub async fn authenticate(
        user_name: &str,
        password: &str,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<OpenIdAuthenticateResponse, reqwest::Error> {
        let url = &context.open_id_connect_template_uris
            .token_endpoint_uri
            .replace("{realm-name}", &context.realm_name);

        let base_url = &context.keycloak_base_url;
        let path = base_url.clone() + &url.to_owned();

        let payload = json!({
            "username": user_name.to_string(),
            "password": password.to_string(),
            "grant_type": "password",
            "client_id": String::from(&context.keycloak_client_id),
            "client_secret": String::from(&context.keycloak_client_secret),
            "code": "".to_string(),
            "redirect_uri": "".to_string(),
        });

        let client = reqwest::Client::new();
        let k_res = client
            .post(path)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"))
            .form(&payload)
            .send()
            .await?.error_for_status()?;
        return k_res.json().await;
    }

    /// Retrieve user details
    ///
    pub async fn get_user_info(access_token: &str, context: &KeycloakOpenIdConnectClientContext) -> Result<OpenIdUserInfoResponse, reqwest::Error> {
        let url = &context
            .open_id_connect_template_uris
            .userinfo_endpoint_uri
            .replace("{realm-name}", &context.realm_name);
        let client = reqwest::Client::new();

        let base_url = &context.keycloak_base_url;
        let path = base_url.clone() + &url.to_owned();

        let res = client.get(&path).bearer_auth(access_token).send().await?;
        res.json().await
    }

    pub async fn validate_token(
        token: &str,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<ValidateTokenResponse, reqwest::Error> {
        let url = &context
            .open_id_connect_template_uris
            .introspection_endpoint_uri
            .replace("{realm-name}",
                     &context.realm_name);

        let payload = json!({
            "client_id": &context.keycloak_client_id,
            "client_secret": &context.keycloak_client_secret,
            "token": token,
        });

        let base_url = &context.keycloak_base_url;
        let path = base_url.clone() + &url.to_owned();

        let client = reqwest::Client::new();
        let k_res = client
            .post(&path)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"))
            .form(&payload)
            .send()
            .await?.error_for_status()?;
        k_res.json().await
    }

    pub async fn introspect(
        data: serde_json::Value,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<String, reqwest::Error> {
        let url = &context.open_id_connect_template_uris.introspection_endpoint_uri;

        let payload = json!({
            "client_id":data["client_id"],
            "client_secret":data["client_secret"],
            "token":data["token"],
        });

        let base_url = &context.keycloak_base_url;
        let path = base_url.clone() + &url.to_owned();

        introspect_token(&path, payload).await
    }

    pub async fn refresh_token(
        refresh_token: &str,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<OpenIdAuthenticateResponse, reqwest::Error> {
        let url = &context
            .open_id_connect_template_uris
            .token_endpoint_uri
            .replace("{realm-name}", &context.realm_name);

        let payload = json!({
            "refresh_token": refresh_token,
            "grant_type":"refresh_token",
            "client_id": &context.keycloak_client_id,
            "client_secret": &context.keycloak_client_secret
        });

        let base_url = &context.keycloak_base_url;
        let path = base_url.clone() + &url.to_owned();

        let client = reqwest::Client::new();
        let k_res = client
            .post(&path)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"))
            .form(&payload)
            .send()
            .await?.error_for_status()?;
        k_res.json().await
    }

    pub async fn end_token_session(
        data: serde_json::Value,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<String, reqwest::Error> {
        let url = &context
            .open_id_connect_template_uris
            .end_session_endpoint_uri.replace("{realm-name}", &context.realm_name);

        let payload = json!({
            "refresh_token":data["token"],
            "grant_type":data["grant_type"],
            "client_id":data["client_id"]
        });

        let base_url = &context.keycloak_base_url;
        let path = base_url.clone() + &url.to_owned();

        let res = get_token(&path, payload).await?;
        let d = json!(res);
        let token = d["access_token"].to_string();
        Ok(token)
    }
}


pub async fn get_token(path: &str, payload: serde_json::Value) -> Result<OpenIdAuthenticateResponse, reqwest::Error> {

    let client = reqwest::Client::new();
    let k_res = client
        .post(path)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"))
        .form(&payload)
        .send()
        .await?.error_for_status()?;
    k_res.json().await
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateTokenRequest {
    pub token: String,
    pub client_secret: String,
    pub client_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateTokenRequestResponse {
    pub exp: i64,
    pub iat: i64
}
pub async fn validate_token(path: &str, payload: ValidateTokenRequest) -> Result<ValidateTokenRequestResponse, reqwest::Error> {
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
