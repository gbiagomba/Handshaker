use thiserror::Error;

#[derive(Error, Debug)]
pub enum HandshakerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("ssl error: {0}")]
    Ssl(String),
    #[error("ssh error: {0}")]
    Ssh(String),
    #[error("rdp error: {0}")]
    Rdp(String),
    #[error("sql error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("csv error: {0}")]
    Csv(#[from] csv::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, HandshakerError>;
