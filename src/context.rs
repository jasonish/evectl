// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

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
        if is_default_root(&self.root) {
            return "evectl".to_string();
        }
        match self.root.file_name() {
            Some(name) => format!("{}-evectl", name.to_string_lossy()),
            None => "evectl".to_string(),
        }
    }
}

/// The default instance root directory, e.g. ~/.config/evectl.
///
/// Only used by the Linux flow: the Windows code has its own data
/// directory, %LOCALAPPDATA%\evectl, see windows::get_evectl_data_dir.
pub(crate) fn default_root() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("evectl"))
}

/// True if root is the default instance directory. The same
/// directory can be spelled differently across invocations
/// (symlinked $HOME components, XDG_CONFIG_HOME), so fall back to
/// comparing canonicalized paths.
fn is_default_root(root: &Path) -> bool {
    let Some(default) = default_root() else {
        return false;
    };
    if root == default {
        return true;
    }
    match (root.canonicalize(), default.canonicalize()) {
        (Ok(root), Ok(default)) => root == default,
        _ => false,
    }
}

/// Validate that an instance directory yields a usable container
/// name prefix: Docker and Podman restrict container names to
/// [a-zA-Z0-9][a-zA-Z0-9_.-]*.
pub(crate) fn validate_root(root: &Path) -> Result<()> {
    if is_default_root(root) {
        return Ok(());
    }
    let name = match root.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => bail!(
            "Invalid instance directory {}: cannot derive an instance name from it",
            root.display()
        ),
    };
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !valid {
        bail!(
            "Invalid instance directory name \"{}\": container names only allow ASCII letters, digits, '_', '.' and '-', starting with a letter or digit",
            name
        );
    }
    Ok(())
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

        // The default instance directory gets a plain prefix. None
        // in environments without a home directory.
        if let Some(default) = default_root() {
            let context = context_with_root(default);
            assert_eq!(context.container_prefix(), "evectl");
        }
    }

    #[test]
    fn validate_root_checks_container_name_charset() {
        assert!(validate_root(Path::new("/srv/sensor1")).is_ok());
        assert!(validate_root(Path::new("/srv/sensor_1.a-b")).is_ok());
        assert!(validate_root(Path::new("/srv/my sensor")).is_err());
        assert!(validate_root(Path::new("/srv/.hidden")).is_err());
        assert!(validate_root(Path::new("/srv/sensör")).is_err());
        // No name to derive at all.
        assert!(validate_root(Path::new("/")).is_err());
        assert!(validate_root(Path::new("/srv/sensor1/..")).is_err());
        if let Some(default) = default_root() {
            assert!(validate_root(&default).is_ok());
        }
    }
}
