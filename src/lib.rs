#[macro_use]
pub extern crate serde_json;
#[macro_use]
pub extern crate serde_derive;
pub extern crate jsonwebtoken as jwt;
pub extern crate reqwest;
pub extern crate serde;

// module that supports a range of keycloak version for backward-compability
pub mod abra;
// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
