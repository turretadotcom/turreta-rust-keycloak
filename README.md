<div align="center">
  <h1>Turreta Rust Keycloak</h1>
  <p>
    <strong>Turreta Rust Keycloak is a crate that enables Rust codes to work with Keycloak.</strong>    
  </p>
    <img src="turreta-rust-keycloak-logo.jpg" height="75%" width="75%">
</div>

## General Requirements

- Rust Stable 1.68.2 or greater
- Keycloak 
  - Supported Keycloak versions:
    - Keycloak 12
    - Keycloak 13
    - Keycloak 14
    - Keycloak 15
    - Keycloak 16
- Ubuntu 22 LTS
- Docker for tests

## Features
- User sign-in
- User access token validation (only for Keycloak clients with confidential access type)
- User access token refresh 
- Keycloak Admin API (for future releases)
## Documentation

TBD

## Tests
We can perform integration tests with multiple versions of Keycloak on our local machines by using Docker and Docker 
compose.  

1. Install Docker
2. Use the **Docker compose command** to spin up the Keycloak instances using **docker-compose.yml**
3. For each Keycloak instance
   - create a realm using the appropriate import JSON file
   - manually create **specific user** with predefined password (**password123**)
   - manually regenerate client secret when needed

| Keycloak version	       | Partial Import Config   	    | User 	          | Realm  	   | Clients  	                                                  |
|-------------------------|------------------------------|-----------------|------------|-------------------------------------------------------------|
| 12.0.4 @localhost:8284	 | kc-12.0.4-realm-export.json  | kc-12.0.4-user-1	 | kc-12.0.4	 | kc-12.0.4-client-public<br/>kc-12.0.4-client-confidential 	 |
| 13.0.1 @localhost:8283	 | kc-13.0.1-realm-export.json	 | kc-13.0.1-user-1	 | kc-13.0.1	 | kc-13.0.1-client-public<br/>kc-13.0.1-client-confidential 	 |
| 14.0.0 @localhost:8282	 | kc-14.0.0-realm-export.json	 | kc-14.0.0-user-1	 | kc-14.0.0	 | kc-14.0.0-client-public<br/>kc-14.0.0-client-confidential 	 |
| 15.1.1 @localhost:8281	 | kc-15.1.1-realm-export.json	 | kc-15.1.1-user-1	 | kc-15.1.1	 | kc-15.1.1-client-confidential<br/>kc-15.1.1-client-public 	 |
| 16.1.1 @localhost:8280	 | kc-16.1.1-realm-export.json	 | kc-16.1.1-user-1	 | kc-16.1.1	 | kc-16.1.1-client-confidential<br/>kc-16.1.1-client-public 	 |


Finally, start the local integration tests using the following command.
```shell
cargo test
```

## License
See LICENSE.txt

## Code of Conduct

TBD
