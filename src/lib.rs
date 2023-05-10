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
    use crate::abra::keycloak_commons::{KeycloakAdminClientContext, KeycloakOpenIdConnectClientContext, OpenIdAuthenticateResponse, WellKnownResponse};
    use super::*;

    // #[actix_rt::test]
//     async fn keycloak_well_known() {
//
//         let test_keycloak_realm_name: String = "turreta-alerts".to_string();
//         let test_keycloak_client_id: String = "turreta-alerts-app".to_string();
//         let test_keycloak_client_secret: String = "hk2IREWspYL3ALJApKQx0X2Q2qCd0fIw".to_string();
//
//         let context = KeycloakOpenIdConnectClientContext::new(test_keycloak_realm_name,
//                                                               test_keycloak_client_id,
//                                                               test_keycloak_client_secret);
//         let well_know = abra::keycloak_facade::KeycloakOpenIdConnect::well_known("http://localhost:8080/auth/", &context);
//         let result = well_know.await;
//
//         let expected_output: WellKnownResponse = serde_json::from_str(r#"{"issuer":"http://localhost:8080/auth/realms/turreta-alerts","authorization_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/auth","token_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token","introspection_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token/introspect","userinfo_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/userinfo","end_session_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/logout","frontchannel_logout_session_supported":true,"frontchannel_logout_supported":true,"jwks_uri":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/certs","check_session_iframe":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"request_object_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"response_modes_supported":["query","fragment","form_post","query.jwt","fragment.jwt","form_post.jwt","jwt"],"registration_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"introspection_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"authorization_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported":true,"scopes_supported":["openid","email","microprofile-jwt","roles","phone","offline_access","web-origins","profile","address"],"request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens":true,"revocation_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/revoke","revocation_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"device_authorization_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/auth/device","backchannel_token_delivery_modes_supported":["poll","ping"],"backchannel_authentication_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/ext/ciba/auth","backchannel_authentication_request_signing_alg_values_supported":["PS384","ES384","RS384","ES256","RS256","ES512","PS256","PS512","RS512"],"require_pushed_authorization_requests":false,"pushed_authorization_request_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/ext/par/request","mtls_endpoint_aliases":{"token_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token","revocation_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/revoke","introspection_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/token/introspect","device_authorization_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/auth/device","registration_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/clients-registrations/openid-connect","userinfo_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/userinfo","pushed_authorization_request_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/ext/par/request","backchannel_authentication_endpoint":"http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect/ext/ciba/auth"}}
// "#).unwrap();
//
//         let actual_output: WellKnownResponse = serde_json::from_str(result.unwrap().as_str()).unwrap();
//
//         assert_eq!(expected_output.issuer, expected_output.issuer);
//         assert_eq!(expected_output.authorization_endpoint, actual_output.authorization_endpoint);
//         assert_eq!(expected_output.introspection_endpoint, actual_output.introspection_endpoint);
//         assert_eq!(expected_output.userinfo_endpoint, actual_output.userinfo_endpoint);
//         assert_eq!(expected_output.end_session_endpoint, actual_output.end_session_endpoint);
//         assert_eq!(expected_output.frontchannel_logout_session_supported, actual_output.frontchannel_logout_session_supported);
//         assert_eq!(expected_output.frontchannel_logout_supported, actual_output.frontchannel_logout_supported);
//         assert_eq!(expected_output.jwks_uri, actual_output.jwks_uri);
//     }


    #[actix_rt::test]
    async fn keycloak_authenticate_user_public_access_type() {
        let test_keycloak_realm_name: String = "turreta-rust-keycloak-na".to_string();
        let test_keycloak_client_id: String = "trk-na-client1".to_string();
        let test_keycloak_client_secret: String = "".to_string();
        let test_keycloak_base_url = "http://localhost:8080/auth/";
        let test_keycloak_username = "na_client1_user1";
        let test_keycloak_user_password = "password";

        let context = KeycloakOpenIdConnectClientContext::new(test_keycloak_realm_name,
                                                              test_keycloak_client_id,
                                                              test_keycloak_client_secret);

        let auth_token = abra::keycloak_openid_service::KeycloakOpenIdConnectService::authenticate(
            test_keycloak_base_url,
            test_keycloak_username,
            test_keycloak_user_password,
            &context);

        let result = auth_token.await;
        let actual_output = result.unwrap();

        assert_eq!(actual_output.token_type, "Bearer");
        assert_eq!(actual_output.expires_in, 300);
        assert_eq!(actual_output.refresh_expires_in, 1800);
    }

    #[actix_rt::test]
    async fn keycloak_authenticate_user_confidential_access_type() {
        let test_keycloak_realm_name: String = "turreta-rust-keycloak-na".to_string();
        let test_keycloak_client_id: String = "trk-na-client2".to_string();
        let test_keycloak_client_secret: String = "wXzRaVXQ3L4ZBUyeMgJLPrjm5gaH19T4".to_string();
        let test_keycloak_base_url = "http://localhost:8080/auth/";
        let test_keycloak_username = "na_client1_user1";
        let test_keycloak_user_password = "password";

        let context = KeycloakOpenIdConnectClientContext::new(test_keycloak_realm_name,
                                                              test_keycloak_client_id,
                                                              test_keycloak_client_secret);
        let auth_token = abra::keycloak_openid_service::KeycloakOpenIdConnectService::authenticate(
            test_keycloak_base_url,
            test_keycloak_username,
            test_keycloak_user_password,
            &context);

        let result = auth_token.await;
        let actual_output = result.unwrap();

        assert_eq!(actual_output.token_type, "Bearer");
        assert_eq!(actual_output.expires_in, 300);
        assert_eq!(actual_output.refresh_expires_in, 1800);
    }

    #[actix_rt::test]
    async fn keycloak_issuer() {
        let test_keycloak_realm_name: String = "turreta-rust-keycloak-na".to_string();
        let test_keycloak_client_id: String = "".to_string();
        let test_keycloak_client_secret: String = "".to_string();
        let test_keycloak_base_url = "http://localhost:8080/auth/";

        let context = KeycloakOpenIdConnectClientContext::new(test_keycloak_realm_name,
                                                              test_keycloak_client_id,
                                                              test_keycloak_client_secret);
        let issuer_resp_future = abra::keycloak_openid_service::KeycloakOpenIdConnectService::get_issuer_details(
            test_keycloak_base_url,
            &context);

        let result = issuer_resp_future.await;
        let actual_output = result.unwrap();

        assert_eq!(actual_output.realm, "turreta-rust-keycloak-na");
        // assert_eq!(actual_output.public_key, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4WU52U+Y+Ijgmqt3dPDKqUg81n5tKY+OTxuiAJ9o2ot/dnLGNXzGd0QnMej12KCUZ8yNuWZ9xDmMi5b7NvAPxBAcZSvuRhg+Jnpcg9V94L3hGZGMrwMqa+MEzml4iSQaw9Qvy1ZYckGyajGdorm+PvvO4WQVuDZmWRAr7KQyUJ6yIi2JzzGHwt5UbmjeOn+JPQXNqQ7gVXlpB4onAfsiHVABxqg4WHTiWdzYxAkS3R7wqqi3az+kVnPue1s+RZb1jO/oq3wW+Fjymr+InR1h0HaM8TK5ekE8GCiO1nS1Q6xJt5LdVaLZktMdSbARowxEqGxt+7rVxqdtht0WywCkQIDAQAB");
        // assert_eq!(actual_output.token_service, "http://localhost:8080/auth/realms/turreta-alerts/protocol/openid-connect");
        // assert_eq!(actual_output.account_service, "http://localhost:8080/auth/realms/turreta-alerts/account");
        assert_eq!(actual_output.tokens_not_before, 0);
    }


    #[actix_rt::test]
    async fn keycloak_user_info() {

        let test_keycloak_realm_name: String = "turreta-rust-keycloak-na".to_string();
        let test_keycloak_client_id: String = "trk-na-client2".to_string();
        let test_keycloak_client_secret: String = "wXzRaVXQ3L4ZBUyeMgJLPrjm5gaH19T4".to_string();
        let test_keycloak_base_url = "http://localhost:8080/auth/";
        let test_keycloak_username = "na_client1_user1";
        let test_keycloak_user_password = "password";

        let context = KeycloakOpenIdConnectClientContext::new(test_keycloak_realm_name,
                                                              test_keycloak_client_id,
                                                              test_keycloak_client_secret);
        let auth_token = abra::keycloak_openid_service::KeycloakOpenIdConnectService::authenticate(
            test_keycloak_base_url,
            test_keycloak_username,
            test_keycloak_user_password,
            &context);

        let result = auth_token.await;
        let actual_output = result.unwrap();


        let user_info = abra::keycloak_openid_service::KeycloakOpenIdConnectService::get_user_info(
            test_keycloak_base_url,
            &actual_output.access_token,
            &context);

        let user_info_result = user_info.await;

        let user_info_actual_output = user_info_result.unwrap();

        assert_eq!(user_info_actual_output.preferred_username, "na_client1_user1");
    }

    // #[actix_rt::test]
    // async fn keycloak_user_info() {
    //
    //     let test_keycloak_realm_name: String = "turreta-alerts".to_string();
    //     let test_keycloak_client_id: String = "turreta-alerts-app".to_string();
    //     let test_keycloak_client_secret: String = "hk2IREWspYL3ALJApKQx0X2Q2qCd0fIw".to_string();
    //     let test_keycloak_base_url = "http://localhost:8080/auth/";
    //     let test_keycloak_username = "alerts";
    //     let test_keycloak_user_password = "password";
    //
    //     let context = KeycloakOpenIdConnectClientContext::new(test_keycloak_realm_name,
    //                                                           test_keycloak_client_id,
    //                                                           test_keycloak_client_secret);
    //     let auth_token = abra::keycloak_openid_service::KeycloakOpenIdConnectService::authenticate(
    //         test_keycloak_base_url,
    //         test_keycloak_username,
    //         test_keycloak_user_password,
    //         &context);
    //
    //     let result = auth_token.await;
    //     let actual_output = result.unwrap();
    //
    //
    //     let user_info = abra::keycloak_openid_service::KeycloakOpenIdConnectService::get_user_info(
    //         test_keycloak_base_url,
    //         &actual_output.access_token,
    //         &context);
    //
    //     let user_info_result = user_info.await;
    //
    //     let user_info_actual_output = user_info_result.unwrap();
    //
    //     assert_eq!(user_info_actual_output.preferred_username, "alerts");
    // }
}
