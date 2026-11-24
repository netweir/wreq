use std::{error::Error as StdError, fmt};

use bytes::Bytes;
use tower::BoxError;

/// A TLS handshake failed because the server rejected the Encrypted Client
/// Hello it was offered (see [`crate::RequestBuilder::ech_config_list`]).
///
/// It is found among a failed request's error sources. A server that knows
/// ECH sends configurations to retry with, which a client may then offer
/// on a new connection; a server that doesn't sends none, and a client may
/// try again without ECH.
#[derive(Debug)]
pub struct EchRejected {
    retry_configs: Option<Bytes>,
    source: BoxError,
}

impl EchRejected {
    pub(crate) fn new(retry_configs: Option<Bytes>, source: BoxError) -> EchRejected {
        EchRejected {
            retry_configs,
            source,
        }
    }

    /// The `ECHConfigList` the server sent to retry with, if any.
    pub fn retry_configs(&self) -> Option<&[u8]> {
        self.retry_configs.as_deref()
    }
}

impl fmt::Display for EchRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.retry_configs {
            Some(_) => f.write_str("the server rejected ECH and sent configurations to retry with"),
            None => f.write_str("the server rejected ECH"),
        }
    }
}

impl StdError for EchRejected {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.source)
    }
}
