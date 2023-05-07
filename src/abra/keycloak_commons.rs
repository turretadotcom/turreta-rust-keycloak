use std::collections::HashMap;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use crate::abra::keycloak_admin_service;
use crate::abra::keycloak_openid_service;
use crate::abra::urls;
use jwt::{decode_header, errors::Error as JwtError};
use crate::abra;
use crate::abra::urls::{AdminURIs, OpenIdConnectURIs};

#[derive(Debug)]
pub struct KeycloakOpenIdConnectClientContext {
    pub openIdConnectTemplateURIs: OpenIdConnectURIs,
    pub keycloak_client_id: String,
    pub keycloak_client_secret: String,
}

impl KeycloakOpenIdConnectClientContext {
    pub fn new(realm_name: &str, keycloak_client_id: String, keycloak_client_secret: String) -> KeycloakOpenIdConnectClientContext {
        KeycloakOpenIdConnectClientContext {
            openIdConnectTemplateURIs: OpenIdConnectURIs {
                issuer_endpoint_uri: "realms/{realm-name}".to_string(),
                openid_configuration_endpoint_uri: "realms/{realm-name}/.well-known/openid-configuration".to_string(),
                authorization_endpoint_uri: "realms/{realm-name}/protocol/openid-connect/auth".to_string(),
                token_endpoint_uri: "realms/{realm-name}/protocol/openid-connect/token".to_string(),
                userinfo_endpoint_uri: "realms/{realm-name}/protocol/openid-connect/userinfo".to_string(),
                introspection_endpoint_uri: "realms/{realm-name}/protocol/openid-connect/token/introspect".to_string(),
                end_session_endpoint_uri: "realms/{realm-name}/protocol/openid-connect/logout".to_string()
            },
            keycloak_client_id,
            keycloak_client_secret
        }
    }
}


pub struct KeycloakAdminClientContext {
    pub adminTemplateURIs: AdminURIs,
    pub keycloak_client_id: String,
    pub keycloak_client_secret: String,
}

impl KeycloakAdminClientContext {
    pub fn new(realm_name: &str, keycloak_client_id: String, keycloak_client_secret: String) -> KeycloakAdminClientContext {

        KeycloakAdminClientContext {
            adminTemplateURIs: AdminURIs {
                url_admin_users: "admin/realms/{realm-name}/users".to_string(),
                url_admin_users_count: "admin/realms/{realm-name}/users/count".to_string(),
                url_admin_user: "admin/realms/{realm-name}/users/{id}".to_string(),
                url_admin_send_update_account: "admin/realms/{realm-name}/users/{id}/execute-actions-email".to_string(),
                url_admin_user_client_roles: "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}".to_string(),
                url_admin_user_realm_roles: "admin/realms/{realm-name}/users/{id}/role-mappings/realm".to_string(),
                url_admin_user_group: "admin/realms/{realm-name}/users/{id}/groups/{group-id}".to_string(),
                url_admin_user_groups: "admin/realms/{realm-name}/users/{id}/groups".to_string(),
            },

            keycloak_client_id,
            keycloak_client_secret
        }
    }
}

#[derive(Debug)]
pub struct KeycloakClientToken {
    pub realm_user_token: String
}


#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct UserConsentRepresentation {
    pub client_id: Option<String>,
    pub created_date: Option<i64>,
    pub granted_client_scopes: Option<Vec<String>>,
    pub last_update_date: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct CredentialRepresentation {
    pub algorithm: Option<String>,
    pub config: serde_json::Value,
    pub counter: Option<i32>,
    pub created_date: Option<i64>,
    pub device: Option<String>,
    pub digits: Option<i32>,
    pub hash_iterations: Option<i32>,
    pub hashed_salted_value: Option<String>,
    pub period: Option<i32>,
    pub salt: Option<String>,
    pub temporary: Option<bool>,
    pub r#type: Option<String>,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct FederatedIdentityRepresentation {
    pub identity_provider: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct UserRepresentation {
    pub access: Option<HashMap<String, bool>>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
    pub client_consents: Option<Vec<UserConsentRepresentation>>,
    pub created_timestamp: Option<i64>,
    pub credentials: Option<Vec<CredentialRepresentation>>,
    pub disableable_credential_types: Option<Vec<String>>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub enabled: Option<bool>,
    pub federated_identities: Option<Vec<FederatedIdentityRepresentation>>,
    pub federation_link: Option<String>,
    pub first_name: Option<String>,
    pub groups: Option<Vec<String>>,
    pub id: Option<String>,
    pub last_name: Option<String>,
    pub not_before: Option<i32>,
    pub origin: Option<String>,
    pub realm_roles: Option<Vec<String>>,
    pub required_actions: Option<Vec<String>>,
    #[serde(rename="self")]
    pub self_: Option<String>,
    pub service_account_client_id: Option<String>,
    pub username: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RoleRepresentationComposites {
    pub client: Option<HashMap<String, String>>,
    pub realm: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct RoleRepresentation {
    pub attributes: Option<HashMap<String, String>>,
    pub client_role: Option<bool>,
    pub composite: Option<bool>,
    pub composites: Option<RoleRepresentationComposites>,
    pub container_id: Option<String>,
    pub description: Option<String>,
    pub id: Option<String>,
    pub name: Option<String>,
}

impl RoleRepresentation {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: Some(id.to_owned()),
            name: Some(name.to_owned()),
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct UserQuery {
    pub brief_representation: Option<bool>,
    pub email: Option<String>,
    pub first: Option<i32>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub max: Option<i32>,
    pub search: Option<String>,
    pub username: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ExecuteActionsEmailQuery<'a> {
    pub lifespan: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<&'a str>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UserGroupsQuery<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<&'a str>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct GroupRepresentation {
    pub id: String,
    pub name: String,
    pub path: String,
}