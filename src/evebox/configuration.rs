// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Platform operations for the shared EveBox server configuration menu.

use crate::context::Context;
use crate::prelude::*;

/// An IPv4 address the EveBox server can bind to.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct BindAddress {
    pub(crate) interface: String,
    pub(crate) address: String,
}

pub(crate) trait Backend {
    /// Whether EveCtl-managed or external OpenSearch/Elasticsearch
    /// datastores are offered. Otherwise the server always uses SQLite.
    fn supports_search_engines(&self) -> bool;
    fn bind_addresses(&self) -> Result<Vec<BindAddress>>;
    /// Interactively reset the EveBox "admin" user's password.
    fn reset_password(&self) -> Result<()>;
}

pub(crate) struct ContainerBackend<'a>(pub(crate) &'a Context);

impl Backend for ContainerBackend<'_> {
    fn supports_search_engines(&self) -> bool {
        true
    }

    fn bind_addresses(&self) -> Result<Vec<BindAddress>> {
        Ok(crate::system::get_interfaces()?
            .into_iter()
            .flat_map(|interface| {
                interface.addr4.into_iter().map(move |address| BindAddress {
                    interface: interface.name.clone(),
                    address,
                })
            })
            .collect())
    }

    fn reset_password(&self) -> Result<()> {
        crate::evebox::server::reset_password(self.0)
    }
}
