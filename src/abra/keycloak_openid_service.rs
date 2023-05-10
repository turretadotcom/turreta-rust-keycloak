use reqwest::header::{HeaderValue, CONTENT_TYPE, ACCEPT};
use crate::abra::keycloak_commons::{KeycloakOpenIdConnectClientContext, OpenIdAuthenticateAndGetTokenRequest, OpenIdAuthenticateResponse, OpenIdIssuerResponse, OpenIdUserInfoResponse};
use crate::abra::urls;
use crate::abra::urls::{OpenIdConnectURIs};
use jwt::{decode_header, errors::Error as JwtError};

/// Keycloak Open ID Connect Service
pub struct KeycloakOpenIdConnectService();

impl KeycloakOpenIdConnectService {

    /// Retrieve available endpoints related to OpenID using the following Keycloak URL.
    ///
    /// E.g., http://{host}:{port}/auth/realms/{realm-name}/.well-known/openid-configuration
    ///
    pub async fn get_open_id_connect_endpoints(base_url: &str, context: &KeycloakOpenIdConnectClientContext) -> Result<String, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs
            .openid_configuration_endpoint_uri
            .replace("{realm-name}", &context.realm_name);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let res = client.get(&path).send().await?;
        res.text().await
    }

    /// Retrieve issue details
    ///
    /// E.g., http://localhost:8080/auth/realms/turreta-alerts
    pub async fn get_issuer_details(base_url: &str, context: &KeycloakOpenIdConnectClientContext) -> Result<OpenIdIssuerResponse, reqwest::Error> {
        let url = &context
            .openIdConnectTemplateURIs
            .issuer_endpoint_uri
            .replace("{realm-name}", &context.realm_name);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let res = client.get(&path).send().await?;
        res.json().await
    }

    /// Authenticate user that belong to a specific realm and client.
    ///
    /// E.g., http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token
    pub async fn authenticate(
        base_url: &str,
        user_name: &str,
        password: &str,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<OpenIdAuthenticateResponse, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs
            .token_endpoint_uri
            .replace("{realm-name}", &context.realm_name);
        let path = base_url.to_owned() + &url.to_owned();

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

    /// Retrieve issue details
    ///
    /// E.g., http://localhost:8080/auth/realms/turreta-alerts
    pub async fn get_user_info(base_url: &str, access_token: &str, context: &KeycloakOpenIdConnectClientContext) -> Result<OpenIdUserInfoResponse, reqwest::Error> {
        let url = &context
            .openIdConnectTemplateURIs
            .userinfo_endpoint_uri
            .replace("{realm-name}", &context.realm_name);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let res = client.get(&path).bearer_auth(access_token).send().await?;
        res.json().await
    }

    pub async fn token_client(
        base_url: &str,
        client_id: &str,
        client_secret: &str,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<String, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs.token_endpoint_uri;

        let payload = json!({
            "client_id": client_id.to_owned(),
            "client_secret": client_secret.to_owned(),
            "grant_type": "client_credentials".to_owned(),
        });

        let path = base_url.to_owned() + &url.to_owned();
        get_token(&path, payload)
            .await
            .map(|res| res.access_token)
    }

    pub async fn introspect(
        base_url: &str,
        data: serde_json::Value,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<String, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs.introspection_endpoint_uri;

        let payload = json!({
            "client_id":data["client_id"],
            "client_secret":data["client_secret"],
            "token":data["token"],
        });

        let path = base_url.to_owned() + &url.to_owned();
        introspect_token(&path, payload).await
    }

    pub fn jwt_decode(token: String) -> Result<jwt::Header, JwtError> {
        decode_header(&token)
    }

    pub async fn refresh_token(
        base_url: &str,
        data: serde_json::Value,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<String, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs.token_endpoint_uri;

        let payload = json!({
            "refresh_token":data["token"],
            "grant_type":data["grant_type"],
            "client_id":data["client_id"]
        });

        let path = base_url.to_owned() + &url.to_owned();

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
