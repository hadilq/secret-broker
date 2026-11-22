//! One error type for the whole crate; every fallible path returns it.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn msg(s: impl Into<String>) -> Self {
        Error::Msg(s.into())
    }

    /// Prefix the error with some context.
    #[must_use]
    pub fn context(self, ctx: impl fmt::Display) -> Self {
        Error::Msg(format!("{ctx}: {self}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Json(e) => write!(f, "invalid JSON: {e}"),
            Error::Msg(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

/// `bail!("...")` returns `Err(Error::Msg(format!(...)))`.
#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => {
        return Err($crate::error::Error::Msg(format!($($t)*)))
    };
}
