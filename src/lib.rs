#[macro_use]
pub extern crate serde_json;
#[macro_use]
pub extern crate serde_derive;
pub extern crate jsonwebtoken as jwt;
pub extern crate reqwest;
pub extern crate serde;

pub mod abra;

/// Test for Keycloak 16.1.1 for public client
///
#[cfg(test)]
mod tests_keycloak_16_1_1_public_client {
    use reqwest::Error;
    use crate::abra::keycloak_commons::{KeycloakOpenIdConnectClientContext, OpenIdAuthenticateResponse, UserQuery};
    use super::*;

    const TEST_KEYCLOAK_BASE_URL: &str = "http://localhost:8280/auth/";
    const TEST_KEYCLOAK_REALM_NAME: &str = "kc-16.1.1";
    const TEST_KEYCLOAK_CLIENT_ID: &str = "kc-16.1.1-client-public";
    const TEST_KEYCLOAK_USERNAME: &str = "kc-16.1.1-user-1";
    const TEST_KEYCLOAK_USER_PASSWORD: &str = "password123";

    /// Authenticate and get the accessToken to be used in subsequent calls
    ///
    async fn  authentication_and_get_token() -> (KeycloakOpenIdConnectClientContext, Result<OpenIdAuthenticateResponse, Error>) {

        let test_keycloak_client_secret: String = "".to_string();

        let context = KeycloakOpenIdConnectClientContext::new(String::from(TEST_KEYCLOAK_REALM_NAME),
                                                              String::from(TEST_KEYCLOAK_CLIENT_ID),
                                                              test_keycloak_client_secret);
        let auth_token = abra::keycloak_openid_service::KeycloakOpenIdConnectService::authenticate(
            TEST_KEYCLOAK_BASE_URL,
            TEST_KEYCLOAK_USERNAME,
            TEST_KEYCLOAK_USER_PASSWORD,
            &context);

        let result = auth_token.await;
        (context, result)
    }

    #[actix_rt::test]
    async fn keycloak_authenticate_user_public_access_type() {
        let test_keycloak_client_secret: String = "".to_string();

        let context = KeycloakOpenIdConnectClientContext::new(String::from(TEST_KEYCLOAK_REALM_NAME),
                                                              String::from(TEST_KEYCLOAK_CLIENT_ID),
                                                              test_keycloak_client_secret);
        let auth_token = abra::keycloak_openid_service::KeycloakOpenIdConnectService::authenticate(
            TEST_KEYCLOAK_BASE_URL,
            TEST_KEYCLOAK_USERNAME,
            TEST_KEYCLOAK_USER_PASSWORD,
            &context);
        let result = auth_token.await;
        let actual_output = result.unwrap();

        assert_eq!(actual_output.token_type, "Bearer");
        assert_eq!(actual_output.expires_in, 300);
        assert_eq!(actual_output.refresh_expires_in, 1800);
    }

    #[actix_rt::test]
    async fn keycloak_issuer() {

        let context = KeycloakOpenIdConnectClientContext::new(String::from(TEST_KEYCLOAK_REALM_NAME),
                                                              "".to_string(),
                                                              "".to_string());
        let issuer_resp_future = abra::keycloak_openid_service::KeycloakOpenIdConnectService::get_issuer_details(
            TEST_KEYCLOAK_BASE_URL,
            &context);

        let result = issuer_resp_future.await;
        let actual_output = result.unwrap();

        assert_eq!(actual_output.realm, TEST_KEYCLOAK_REALM_NAME);
        assert_eq!(actual_output.tokens_not_before, 0);
    }


    #[actix_rt::test]
    async fn keycloak_user_info() {
        let (context, result) = authentication_and_get_token().await;
        let actual_output = result.unwrap();

        let user_info = abra::keycloak_openid_service::KeycloakOpenIdConnectService::get_user_info(
            TEST_KEYCLOAK_BASE_URL,
            &actual_output.access_token,
            &context);

        let user_info_result = user_info.await;
        let user_info_actual_output = user_info_result.unwrap();
        assert_eq!(user_info_actual_output.preferred_username, "kc-16.1.1-user-1");
    }

    /// Unable to validate token when client access type is public
    /// See https://stackoverflow.com/questions/51132711/introspection-endpoint-of-keycloak-server
    ///
    #[actix_rt::test]
    async fn keycloak_validate_valid_token() {
        let (context, result) = authentication_and_get_token().await;
        let actual_output = result.unwrap();

        let token_validation_future = abra::keycloak_openid_service::KeycloakOpenIdConnectService::validate_token(
            TEST_KEYCLOAK_BASE_URL,
            &actual_output.access_token,
            &context);

        let token_validation_result = token_validation_future.await;
        let token_validation_actual_result = token_validation_result.unwrap_err();
        assert_eq!(token_validation_actual_result.status().unwrap(), 403);
    }

    /// Unable to validate token when client access type is public
    /// See https://stackoverflow.com/questions/51132711/introspection-endpoint-of-keycloak-server
    ///
    #[actix_rt::test]
    async fn keycloak_validate_invalid_token() {
        let (context, result) = authentication_and_get_token().await;
        let _actual_output = result.unwrap();

        let token_validation_future = abra::keycloak_openid_service::KeycloakOpenIdConnectService::validate_token(
            TEST_KEYCLOAK_BASE_URL,
            "invalid_token",
            &context);

        let token_validation_result = token_validation_future.await;
        let token_validation_actual_result = token_validation_result.unwrap_err();
        assert_eq!(token_validation_actual_result.status().unwrap(), 403);
    }
}

/// Test for Keycloak 16.1.1 for confidential client
///
#[cfg(test)]
mod tests_keycloak_16_1_1_confidential_client {
    use reqwest::Error;
    use crate::abra::keycloak_commons::{KeycloakOpenIdConnectClientContext, OpenIdAuthenticateResponse, UserQuery};
    use super::*;

    const TEST_KEYCLOAK_BASE_URL: &str = "http://localhost:8280/auth/";
    const TEST_KEYCLOAK_REALM_NAME: &str = "kc-16.1.1";
    const TEST_KEYCLOAK_CLIENT_ID: &str = "kc-16.1.1-client-confidential";
    const TEST_KEYCLOAK_USERNAME: &str = "kc-16.1.1-user-1";
    const TEST_KEYCLOAK_USER_PASSWORD: &str = "password123";

    /// Authenticate and get the accessToken to be used in subsequent calls
    ///
    async fn  authentication_and_get_token() -> (KeycloakOpenIdConnectClientContext, Result<OpenIdAuthenticateResponse, Error>) {

        let test_keycloak_client_secret: String = "rxfOvlFl1wmrO73MDpshFMGk9RL3VuzP".to_string();

        let context = KeycloakOpenIdConnectClientContext::new(String::from(TEST_KEYCLOAK_REALM_NAME),
                                                              String::from(TEST_KEYCLOAK_CLIENT_ID),
                                                              test_keycloak_client_secret);
        let auth_token = abra::keycloak_openid_service::KeycloakOpenIdConnectService::authenticate(
            TEST_KEYCLOAK_BASE_URL,
            TEST_KEYCLOAK_USERNAME,
            TEST_KEYCLOAK_USER_PASSWORD,
            &context);

        let result = auth_token.await;
        (context, result)
    }

    #[actix_rt::test]
    async fn keycloak_authenticate_user_confidential_access_type() {
        let test_keycloak_client_secret: String = "rxfOvlFl1wmrO73MDpshFMGk9RL3VuzP".to_string();

        let context = KeycloakOpenIdConnectClientContext::new(String::from(TEST_KEYCLOAK_REALM_NAME),
                                                              String::from(TEST_KEYCLOAK_CLIENT_ID),
                                                              test_keycloak_client_secret);
        let auth_token = abra::keycloak_openid_service::KeycloakOpenIdConnectService::authenticate(
            TEST_KEYCLOAK_BASE_URL,
            TEST_KEYCLOAK_USERNAME,
            TEST_KEYCLOAK_USER_PASSWORD,
            &context);
        let result = auth_token.await;
        let actual_output = result.unwrap();

        assert_eq!(actual_output.token_type, "Bearer");
        assert_eq!(actual_output.expires_in, 300);
        assert_eq!(actual_output.refresh_expires_in, 1800);
    }

    #[actix_rt::test]
    async fn keycloak_issuer() {
        let context = KeycloakOpenIdConnectClientContext::new(String::from(TEST_KEYCLOAK_REALM_NAME),
                                                              "".to_string(),
                                                              "".to_string());
        let issuer_resp_future = abra::keycloak_openid_service::KeycloakOpenIdConnectService::get_issuer_details(
            TEST_KEYCLOAK_BASE_URL,
            &context);

        let result = issuer_resp_future.await;
        let actual_output = result.unwrap();

        assert_eq!(actual_output.realm, TEST_KEYCLOAK_REALM_NAME);
        assert_eq!(actual_output.tokens_not_before, 0);
    }


    #[actix_rt::test]
    async fn keycloak_user_info() {
        let (context, result) = authentication_and_get_token().await;
        let actual_output = result.unwrap();

        let user_info = abra::keycloak_openid_service::KeycloakOpenIdConnectService::get_user_info(
            TEST_KEYCLOAK_BASE_URL,
            &actual_output.access_token,
            &context);

        let user_info_result = user_info.await;
        let user_info_actual_output = user_info_result.unwrap();
        assert_eq!(user_info_actual_output.preferred_username, "kc-16.1.1-user-1");
    }

    ///
    #[actix_rt::test]
    async fn keycloak_validate_valid_token() {
        let (context, result) = authentication_and_get_token().await;
        let actual_output = result.unwrap();

        let token_validation_future = abra::keycloak_openid_service::KeycloakOpenIdConnectService::validate_token(
            TEST_KEYCLOAK_BASE_URL,
            &actual_output.access_token,
            &context);

        let token_validation_result = token_validation_future.await;
        let token_validation_actual_result = token_validation_result.unwrap();
        assert_eq!(token_validation_actual_result.active, true);
    }

    #[actix_rt::test]
    async fn keycloak_validate_invalid_token() {
        let (context, result) = authentication_and_get_token().await;
        let _actual_output = result.unwrap();

        let token_validation_future = abra::keycloak_openid_service::KeycloakOpenIdConnectService::validate_token(
            TEST_KEYCLOAK_BASE_URL,
            "invalid_token",
            &context);

        let token_validation_result = token_validation_future.await;
        let token_validation_actual_result = token_validation_result.unwrap();
        assert_eq!(token_validation_actual_result.active, false);
    }
}

/// Test for Keycloak 15.1.1 for public client
///
#[cfg(test)]
mod tests_keycloak_15_1_1_public_client {

}

#[cfg(test)]
mod tests_keycloak_15_1_1_confidential_client {

}
