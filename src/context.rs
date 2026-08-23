// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::path::PathBuf;

use crate::{
    config::Config,
    container::{Container, ContainerManager, DEFAULT_EVEBOX_IMAGE, DEFAULT_SURICATA_IMAGE},
};

#[derive(Clone)]
pub(crate) struct Context {
    pub root: PathBuf,

    pub config: Config,

    pub manager: ContainerManager,

    // Stash some image names for easy access.
    pub suricata_image: String,
    pub evebox_image: String,
}

impl Context {
    pub(crate) fn new(config: Config, root: PathBuf, manager: ContainerManager) -> Self {
        let suricata_image = image_name(&config, Container::Suricata);
        let evebox_image = image_name(&config, Container::EveBox);
        Self {
            root,
            config,
            manager,
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

    /// Prefix for container names, derived from the instance
    /// directory name so multiple instances don't collide. The
    /// default instance directory uses a plain "evectl" prefix.
    pub(crate) fn container_prefix(&self) -> String {
        if Some(&self.root) == default_root().as_ref() {
            return "evectl".to_string();
        }
        match self.root.file_name() {
            Some(name) => format!("{}-evectl", name.to_string_lossy()),
            None => "evectl".to_string(),
        }
    }
}

/// The default instance root directory, e.g. ~/.config/evectl on
/// Linux.
pub(crate) fn default_root() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("evectl"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::DockerManager;

    fn context_with_root(root: PathBuf) -> Context {
        Context::new(
            Config::default(),
            root,
            ContainerManager::Docker(DockerManager::new()),
        )
    }

    #[test]
    fn container_prefix_from_directory_name() {
        let context = context_with_root(PathBuf::from("/home/user/sensor1"));
        assert_eq!(context.container_prefix(), "sensor1-evectl");

        // Legacy instances named "evectl" keep their prefix.
        let context = context_with_root(PathBuf::from("/home/user/evectl"));
        assert_eq!(context.container_prefix(), "evectl-evectl");

        // The default instance directory gets a plain prefix.
        let default = default_root().unwrap();
        let context = context_with_root(default);
        assert_eq!(context.container_prefix(), "evectl");
    }
}
