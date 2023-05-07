use std::collections::HashMap;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use crate::abra::keycloak_admin_service;
use crate::abra::keycloak_openid_service;
use crate::abra::urls;
use jwt::{decode_header, errors::Error as JwtError};
use crate::abra;
use crate::abra::keycloak_commons::{ExecuteActionsEmailQuery, GroupRepresentation, KeycloakAdminClientContext, KeycloakOpenIdConnectClientContext, RoleRepresentation, UserGroupsQuery, UserQuery, UserRepresentation};

pub struct KeycloakAdmin();
pub struct KeycloakOpenIdConnect();

impl KeycloakOpenIdConnect {

    /// E.g., http://localhost:8080/auth/realms/turreta-alerts/.well-known/openid-configuration
    pub async fn well_known(base_url: &str, context: &KeycloakOpenIdConnectClientContext) -> Result<String, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs
            .openid_configuration_endpoint_uri
            .replace("{realm-name}", &context.realm_name);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let res = client.get(&path).send().await?;
        res.text().await
    }

    /// E.g., http://localhost:8080/auth/realms/turreta-alerts
    pub async fn issuer(base_url: &str, context: &KeycloakOpenIdConnectClientContext) -> Result<String, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs.issuer_endpoint_uri;
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let res = client.get(&path).send().await?;
        res.text().await
    }

    /// E.g., http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token
    pub async fn token(
        base_url: &str,
        data: serde_json::Value,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<String, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs.token_endpoint_uri;

        let payload = json!({
            "username":"alerts",
            "password":"password",
            "client_id":data["client_id"],
            "grant_type":data["grant_type"],
            // "client_secret": "hk2IREWspYL3ALJApKQx0X2Q2qCd0fIw",
            // "client_id": "turreta-alerts-app"
            "client_secret":data["client_secret"],
            "client_id":data["client_id"],
            "code":data["code"],
            "redirect_uri":data["redirect_uri"],
        });

        let path = base_url.to_owned() + &url.to_owned();
        keycloak_openid_service::get_token(&path, payload)
            .await
            .map(|res| res.access_token)
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
        keycloak_openid_service::get_token(&path, payload)
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
        keycloak_openid_service::introspect_token(&path, payload).await
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

        let res = keycloak_openid_service::get_token(&path, payload).await?;
        let d = json!(res);
        let token = d["access_token"].to_string();
        Ok(token)
    }
}

impl KeycloakAdmin {
    pub async fn create_user(
        base_url: &str,
        data: &UserRepresentation,
        realm: &str,
        token: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<Option<String>, reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_users
            .replace("{realm-name}", realm);
        let payload =  serde_json::to_value(data).unwrap();

        let path = base_url.to_owned() + &url.to_owned();
        let response = keycloak_admin_service::payload_bearer_request(&path, payload, token).await?;

        if let Some(location) = response.headers().get("location").and_then(|location| location.to_str().ok()) {
            Ok(location.rsplitn(2, '/').next().map(|id| id.to_owned()))
        } else {
            Ok(None)
        }
    }

    pub async fn update_user(
        base_url: &str,
        data: &UserRepresentation,
        realm: &str,
        token: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<(), reqwest::Error> {
        let url = context.adminTemplateURIs
            .url_admin_user
            .replace("{realm-name}", realm)
            .replace("{id}", data.id.as_ref().unwrap());
        let payload =  serde_json::to_value(data).unwrap();

        let path = base_url.to_owned() + &url.to_owned();
        let client = reqwest::Client::new();
        client
            .put(&path)
            .bearer_auth(token.to_string())
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .json(&payload)
            .send()
            .await?.error_for_status()
            .map(|_| {})
    }

    pub async fn get_user(
        base_url: &str,
        realm: &str,
        user_id: &str,
        token: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<Option<UserRepresentation>, reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_user
            .replace("{realm-name}", realm)
            .replace("{id}", user_id);
        
        let path = base_url.to_owned() + &url.to_owned();
        let client = reqwest::Client::new();
        let response = client
            .get(&path)
            .bearer_auth(token.to_string())
            .send()
            .await?.error_for_status()?;
        let json = response.json().await?;

        if let Ok(user) = serde_json::from_value(json) {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn get_users(
        base_url: &str,
        realm: &str,
        query: &UserQuery,
        token: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<Vec<UserRepresentation>, reqwest::Error> {

        let url = &context.adminTemplateURIs
            .url_admin_users
            .replace("{realm-name}", realm);
        
        let path = base_url.to_owned() + &url.to_owned();
        let client = reqwest::Client::new();
        let response = client
            .get(&path)
            .bearer_auth(token.to_string())
            .query(&query)
            .send()
            .await?.error_for_status()?;
        let json = response.json().await?;

        if let Ok(users) = serde_json::from_value(json) {
            Ok(users)
        } else {
            Ok(Vec::new())
        }
    }

    pub async fn delete_user(
        base_url: &str,
        user_id: &str,
        realm: &str,
        token: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<(), reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_user
            .replace("{realm-name}", realm)
            .replace("{id}", user_id);

        let path = base_url.to_owned() + &url.to_owned();
        let client = reqwest::Client::new();
        client
            .delete(&path)
            .bearer_auth(token.to_string())
            .send()
            .await?.error_for_status()?;
        Ok(())
    }

    pub async fn users_count(
        base_url: &str,
        realm: &str,
        bearer: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<Option<u64>, reqwest::Error> {
        let url = &context.adminTemplateURIs.url_admin_users_count;

        let path = base_url.to_owned() + &url.to_owned();
        let res = keycloak_admin_service::bearer_get_request(&path, bearer).await?;
        if let serde_json::Value::Number(count) = res.json().await? {
            Ok(count.as_u64())
        } else {
            Ok(None)
        }
    }

    pub async fn user_info(
        base_url: &str,
        bearer: &str,
        context: &KeycloakOpenIdConnectClientContext
    ) -> Result<serde_json::Value, reqwest::Error> {
        let url = &context.openIdConnectTemplateURIs.userinfo_endpoint_uri;
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.post(&path).bearer_auth(bearer).send().await?.error_for_status()?;
        Ok(json!(k_res.json().await?))
    }

    pub async fn add_user_group<'a>(
        base_url: &'a str,
        realm: &'a str,
        user_id: &'a str,
        group_id: &'a str,
        bearer: &'a str,
        context: &KeycloakAdminClientContext
    ) -> Result<(), reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_user_group
            .replace("{realm-name}", realm)
            .replace("{id}", user_id)
            .replace("{group-id}", group_id);
        
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.put(&path).bearer_auth(bearer)
            .json(&json!({
                "realm": realm.to_owned(),
                "userId": user_id.to_owned(),
                "groupId": group_id.to_owned(),
            }))
            .send().await?.error_for_status()?;
        k_res.text().await?;
        Ok(())
    }

    pub async fn remove_user_group<'a>(
        base_url: &'a str,
        realm: &'a str,
        user_id: &'a str,
        group_id: &'a str,
        bearer: &'a str,
        context: &KeycloakAdminClientContext
    ) -> Result<(), reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_user_group
            .replace("{realm-name}", realm)
            .replace("{id}", user_id)
            .replace("{group-id}", group_id);
        
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.delete(&path).bearer_auth(bearer)
            .json(&json!({
                "realm": realm.to_owned(),
                "userId": user_id.to_owned(),
                "groupId": group_id.to_owned(),
            }))
            .send().await?.error_for_status()?;
        k_res.text().await?;
        Ok(())
    }

    pub async fn user_representation(
        base_url: &str,
        realm: &str,
        id: &str,
        bearer: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<Option<UserRepresentation>, reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_user
            .replace("{realm-name}", realm)
            .replace("{id}", id);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.get(&path).bearer_auth(bearer).send().await?.error_for_status()?;
        Ok(serde_json::from_value(k_res.json().await?).ok())
    }

    pub async fn user_groups(
        base_url: &str,
        realm: &str,
        id: &str,
        query: Option<UserGroupsQuery<'_>>,
        bearer: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<Option<Vec<GroupRepresentation>>, reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_user_groups
            .replace("{realm-name}", realm)
            .replace("{id}", id);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let request = client.get(&path).bearer_auth(bearer);
        let request = if let Some(query) = query {
            request.query(&query)
        } else {
            request
        };
        let k_res = request.send().await?.error_for_status()?;
        Ok(serde_json::from_value(k_res.json().await?).ok())
    }

    pub async fn add_realm_roles_to_user(
        base_url: &str,
        realm: &str,
        user_id: &str,
        roles: &[RoleRepresentation],
        bearer: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<(), reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_user_realm_roles
            .replace("{realm-name}", realm)
            .replace("{id}", user_id);
        
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.post(&path).bearer_auth(bearer)
            .json(roles)
            .send().await?.error_for_status()?;
        k_res.text().await?;
        Ok(())
    }

    pub async fn add_client_roles_to_user(
        base_url: &str,
        realm: &str,
        user_id: &str,
        client_id: &str,
        roles: &[RoleRepresentation],
        bearer: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<(), reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_user_client_roles
            .replace("{realm-name}", realm)
            .replace("{id}", user_id)
            .replace("{client-id}", client_id);
        
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.post(&path).bearer_auth(bearer)
            .json(roles)
            .send().await?.error_for_status()?;
        k_res.text().await?;
        Ok(())
    }

    pub async fn send_update_account(
        base_url: &str,
        realm: &str,
        user_id: &str,
        actions: &[&str],
        lifespan: i32,
        client_id: Option<&str>,
        redirect_uri: Option<&str>,
        bearer: &str,
        context: &KeycloakAdminClientContext
    ) -> Result<(), reqwest::Error> {
        let url = &context.adminTemplateURIs
            .url_admin_send_update_account
            .replace("{realm-name}", realm)
            .replace("{id}", user_id);
        
        let client = reqwest::Client::new();
        let query = ExecuteActionsEmailQuery {
            lifespan, client_id, redirect_uri,
        };

        let path = base_url.to_owned() + &url.to_owned();
        client.put(&path).bearer_auth(bearer)
            .query(&query)
            .json(&actions)
            .send().await?.error_for_status()?;
        Ok(())
    }
}

