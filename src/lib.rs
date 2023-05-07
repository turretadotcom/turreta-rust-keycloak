#[macro_use]
pub extern crate serde_json;
#[macro_use]
pub extern crate serde_derive;
pub extern crate jsonwebtoken as jwt;
pub extern crate reqwest;
pub extern crate serde;

pub mod abra;

#[cfg(test)]
mod tests {
    use crate::abra::keycloak_commons::{KeycloakAdminClientContext, KeycloakOpenIdConnectClientContext};
    use super::*;

    #[actix_rt::test]
    async fn keycloak_well_known() {
        let context = KeycloakOpenIdConnectClientContext::new("turreta-alerts".to_string(),
                                                              "turreta-alerts-app".to_string(),
                                                              "hk2IREWspYL3ALJApKQx0X2Q2qCd0fIw".to_string());
        let well = abra::keycloak_facade::KeycloakOpenIdConnect::well_known("http://localhost:8080/auth/", &context);
        let o = well.await;

        let expected_output = r#"{"issuer":"http://localhost:8080/auth/realms/turreta-alerts","authorization_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/auth","token_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token","introspection_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token/introspect","userinfo_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/userinfo","end_session_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/logout","frontchannel_logout_session_supported":true,"frontchannel_logout_supported":true,"jwks_uri":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/certs","check_session_iframe":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"request_object_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"response_modes_supported":["query","fragment","form_post","query.jwt","fragment.jwt","form_post.jwt","jwt"],"registration_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"introspection_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"authorization_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported":true,"scopes_supported":["openid","email","microprofile-jwt","roles","phone","offline_access","web-origins","profile","address"],"request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens":true,"revocation_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/revoke","revocation_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"device_authorization_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/auth/device","backchannel_token_delivery_modes_supported":["poll","ping"],"backchannel_authentication_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/ext/ciba/auth","backchannel_authentication_request_signing_alg_values_supported":["PS384","ES384","RS384","ES256","RS256","ES512","PS256","PS512","RS512"],"require_pushed_authorization_requests":false,"pushed_authorization_request_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/ext/par/request","mtls_endpoint_aliases":{"token_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token","revocation_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/revoke","introspection_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token/introspect","device_authorization_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/auth/device","registration_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/clients-registrations/openid-connect","userinfo_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/userinfo","pushed_authorization_request_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/ext/par/request","backchannel_authentication_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/ext/ciba/auth"}}
"#;
        let actual_output: String = o.unwrap();

        println!("AAA {}", actual_output);
        println!("BBB {}", expected_output);

        assert!(expected_output.to_string().eq(&actual_output));
    }


    // #[actix_rt::test]
    // async fn keycloak_openidconnect_authentication() {
    //     let context = KeycloakOpenIdConnectClientContext::new("",
    //                                                           "turreta-alerts-app".to_string(),
    //                                                           "hk2IREWspYL3ALJApKQx0X2Q2qCd0fIw".to_string());
    //     let well = abra::keycloak_facade::KeycloakOpenIdConnect::token("http://localhost:8080/auth/", &context);
    //     let o = well.await;
    //     println!("{}", o.unwrap());
    // }
}
