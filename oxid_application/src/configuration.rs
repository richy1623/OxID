use std::time::Duration;

use config::{Config, ConfigError, Environment};
use derive_debug::Dbg;
use serde::{Deserialize, Deserializer};

#[derive(Dbg, Deserialize, Clone)]
pub struct AppConfig {
    /// server_port: the port the authentication application should be served on [default: 8080]
    pub server_port: u16,
    /// refresh_token_lifespan: length of time a refresh token should be valid (represented as an iso8601 duration) [default: PT12H]
    #[serde(deserialize_with = "parse_iso8601_duration")]
    pub refresh_token_lifespan: Duration,
    /// authentication_token_lifespan: length of time a refresh token should be valid (represented as an iso8601 duration) [default: PT30M]
    #[serde(deserialize_with = "parse_iso8601_duration")]
    pub authentication_token_lifespan: Duration,
    /// database_url: the url of the postgres DB that the application should use for persistent storage
    #[dbg(placeholder = "****")]
    pub database_url: String,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let s = Config::builder()
            .set_default("server_port", 8080)?
            .set_default("refresh_token_lifespan", "PT12H")?
            .set_default("authentication_token_lifespan", "PT30M")?
            .add_source(Environment::with_prefix("APP"))
            .build()?;

        s.try_deserialize()
    }
}

fn parse_iso8601_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    let iso_duration = iso8601::duration(&s).map_err(serde::de::Error::custom)?;

    Duration::try_from(iso_duration).map_err(|err| serde::de::Error::custom(err))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn get_test_config() -> AppConfig {
        AppConfig {
            server_port: 8080,
            refresh_token_lifespan: Duration::from_secs(5),
            authentication_token_lifespan: Duration::from_secs(2),
            database_url: "postgres://username:password@localhost:5430/postgres".to_string(),
        }
    }
}
