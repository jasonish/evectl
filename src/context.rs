// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::path::PathBuf;

use crate::{
    config::Config,
    container::{Container, ContainerManager, DEFAULT_EVEBOX_IMAGE, DEFAULT_SURICATA_IMAGE},
    service::ServiceManager,
};

#[derive(Clone)]
pub(crate) struct Context {
    pub root: PathBuf,

    pub config: Config,

    pub manager: ContainerManager,
    pub service_manager: ServiceManager,

    // Stash some image names for easy access.
    pub suricata_image: String,
    pub evebox_image: String,
}

impl Context {
    pub(crate) fn new(config: Config, root: PathBuf, manager: ContainerManager) -> Self {
        let suricata_image = image_name(&config, Container::Suricata);
        let evebox_image = image_name(&config, Container::EveBox);

        // Create service manager based on platform
        let service_manager = if cfg!(windows) {
            #[cfg(windows)]
            {
                let state_dir = root.join("data").join("services");
                ServiceManager::process(state_dir)
            }
            #[cfg(not(windows))]
            ServiceManager::container(manager)
        } else {
            ServiceManager::container(manager)
        };

        Self {
            root,
            config,
            manager,
            service_manager,
            suricata_image,
            evebox_image,
        }
    }

    /// Given a container type, return the image name.
    ///
    /// Normally this will be the hardcoded default, but we do allow
    /// it to be overridden in the configuration.
    pub(crate) fn image_name(&self, container: Container) -> String {
        image_name(&self.config, container)
    }

    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }
}

/// Given a container type, return the image name.
///
/// Normally this will be the hardcoded default, but we do allow
/// it to be overridden in the configuration.
pub(crate) fn image_name(config: &Config, container: Container) -> String {
    match container {
        Container::Suricata => config
            .suricata
            .image
            .as_deref()
            .unwrap_or(DEFAULT_SURICATA_IMAGE)
            .to_string(),
        Container::EveBox => config
            .evebox_server
            .image
            .as_deref()
            .unwrap_or(DEFAULT_EVEBOX_IMAGE)
            .to_string(),
    }
}
