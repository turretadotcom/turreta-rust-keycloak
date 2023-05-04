use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdConnectURIs {
    pub issuer_endpoint_uri: String,
    pub openid_configuration_endpoint_uri: String,
    pub authorization_endpoint_uri: String,
    pub token_endpoint_uri: String,
    pub userinfo_endpoint_uri: String,
    pub introspection_endpoint_uri: String,
    pub end_session_endpoint_uri: String,
    /*url_logout : &'static str,
    url_certs : &'static str,
    url_introspect : &'static str,
    url_entitlement : &'static str,
    url_auth : &'static str,*/
}

#[derive(Debug)]
pub struct AdminURIs {
    pub url_admin_users: String,
    pub url_admin_users_count: String,
    pub url_admin_user : String,
    pub url_admin_send_update_account : String,
    pub url_admin_user_client_roles : String,
    pub url_admin_user_realm_roles: String,
    pub url_admin_user_group : String,
    pub url_admin_user_groups : String,
}
