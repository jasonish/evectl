// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The `uninstall` command: stop all services and remove an
//! instance's data, optionally its configuration, and with `--all`
//! everything else EveCtl put on the system.
//!
//! Only the pieces EveCtl created are ever deleted: the `data` and
//! `config` directories and `evectl.toml`. The instance directory
//! itself is only removed once it is empty, and never when it is the
//! current directory, as under the legacy layout that can be a
//! directory holding unrelated files.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::config::SearchEngine;
use crate::container::Container;
use crate::prelude::*;
use crate::{elastic, systemd};

/// Returns Ok(false) if the uninstall was canceled at a prompt.
pub(crate) fn uninstall(context: &Context, config: bool, all: bool, yes: bool) -> Result<bool> {
    let remove_config = config || all;

    // Resolved up front as the root may no longer exist by the time
    // the binary prompt is reached.
    let is_default_root = crate::context::is_default_root(&context.root);

    // Container images and the EveCtl binary are shared between
    // instances, so a full uninstall is only offered for the default
    // instance.
    if all && !is_default_root {
        bail!(
            "--all is only supported for the default instance directory, use --config to remove instance {}",
            context.root.display()
        );
    }

    if !yes && !std::io::stdin().is_terminal() {
        bail!("No terminal available for confirmation, pass --yes to run without prompting");
    }

    let containers = existing_containers(context);
    let mut paths = vec![context.data_dir()];
    if remove_config {
        paths.push(context.config_dir());
        paths.push(config_file(context));
    }
    paths.retain(|path| path.exists());
    let remove_root = remove_config && root_removable(context);
    let images = if all {
        existing_images(context)
    } else {
        vec![]
    };
    let remove_systemd = all && systemd::is_enabled();
    let mut binary = if all {
        crate::selfupdate::removable_exe()
    } else {
        None
    };

    println!("The following will be removed:");
    for name in &containers {
        println!("  container {}", name);
    }
    for path in &paths {
        println!("  {}", path.display());
    }
    if remove_root {
        println!("  {} (if empty)", context.root.display());
    }
    if remove_systemd {
        println!("  systemd unit evectl.service");
    }
    for image in &images {
        println!("  image {}", image);
    }
    if let Some(binary) = &binary {
        println!("  {}", binary.display());
    }

    if !yes && !crate::prompt::confirm_destructive("Proceed with uninstall?") {
        info!("Uninstall canceled");
        return Ok(false);
    }

    if !crate::stop_all(context) {
        bail!("Failed to stop services, nothing removed");
    }
    for name in &containers {
        context.manager.quiet_rm(name);
    }

    let mut errors: Vec<String> = vec![];

    if remove_systemd && let Err(err) = systemd::remove() {
        errors.push(format!("Failed to remove systemd unit: {}", err));
    }

    for path in &paths {
        if let Err(err) = remove_path(context, path) {
            errors.push(err.to_string());
        }
    }
    if remove_root && let Err(err) = remove_root_directory(context) {
        errors.push(err.to_string());
    }

    // When interactive, keep prompting through the layers the flags
    // didn't already cover: configuration, the instance directory,
    // the systemd unit, and finally the binary.
    if !yes {
        if !remove_config {
            let mut config_removed = true;

            let config_dir = context.config_dir();
            if config_dir.exists() {
                if crate::prompt::confirm_destructive(&format!(
                    "Also remove the configuration directory {}?",
                    config_dir.display()
                )) {
                    if let Err(err) = remove_path(context, &config_dir) {
                        errors.push(err.to_string());
                        config_removed = false;
                    }
                } else {
                    config_removed = false;
                }
            }

            let config_file = config_file(context);
            if config_file.exists() {
                if crate::prompt::confirm_destructive(&format!(
                    "Also remove the configuration file {}?",
                    config_file.display()
                )) {
                    if let Err(err) = remove_path(context, &config_file) {
                        errors.push(err.to_string());
                        config_removed = false;
                    }
                } else {
                    config_removed = false;
                }
            }

            // Only offer to remove the instance directory once
            // nothing the user chose to keep remains in it.
            if config_removed
                && root_removable(context)
                && crate::prompt::confirm_destructive(&format!(
                    "Also remove the instance directory {}?",
                    context.root.display()
                ))
                && let Err(err) = remove_root_directory(context)
            {
                errors.push(err.to_string());
            }
        }

        if !all
            && systemd::is_enabled()
            && crate::prompt::confirm_destructive("Also remove the systemd unit evectl.service?")
            && let Err(err) = systemd::remove()
        {
            errors.push(format!("Failed to remove systemd unit: {}", err));
        }

        // The binary is shared between instances, so only offer its
        // removal for the default instance.
        if !all
            && is_default_root
            && let Some(exe) = crate::selfupdate::removable_exe()
            && crate::prompt::confirm_destructive(&format!(
                "Also remove the EveCtl binary {}?",
                exe.display()
            ))
        {
            binary = Some(exe);
        }
    }

    for image in &images {
        info!("Removing image {}", image);
        if let Err(err) = context.manager.remove_image(image) {
            errors.push(format!("Failed to remove image {}: {}", image, err));
        }
    }

    if let Some(binary) = &binary {
        info!("Removing {}", binary.display());
        if let Err(err) = std::fs::remove_file(binary) {
            errors.push(format!("Failed to remove {}: {}", binary.display(), err));
        }
    }

    if errors.is_empty() {
        info!("Uninstall complete");
        Ok(true)
    } else {
        bail!(
            "Uninstall completed with errors:\n- {}",
            errors.join("\n- ")
        )
    }
}

fn config_file(context: &Context) -> PathBuf {
    context.root.join("evectl.toml")
}

/// Whether the instance directory itself may be removed: never when
/// it is the current directory.
fn root_removable(context: &Context) -> bool {
    let Ok(root) = context.root.canonicalize() else {
        return false;
    };
    match std::env::current_dir().and_then(|dir| dir.canonicalize()) {
        Ok(cwd) => root != cwd,
        Err(_) => false,
    }
}

/// Remove the instance directory, but only if it's empty: anything
/// EveCtl didn't create is left alone.
fn remove_root_directory(context: &Context) -> Result<()> {
    let root = &context.root;
    if !root.exists() {
        return Ok(());
    }
    match std::fs::remove_dir(root) {
        Ok(()) => {
            info!("Removed {}", root.display());
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            info!(
                "Leaving {} in place as it contains other files",
                root.display()
            );
            Ok(())
        }
        Err(err) => bail!("Failed to remove {}: {}", root.display(), err),
    }
}

fn remove_path(context: &Context, path: &Path) -> Result<()> {
    if path.is_dir() {
        remove_directory(context, path)
    } else {
        info!("Removing {}", path.display());
        std::fs::remove_file(path).with_context(|| format!("Failed to remove {}", path.display()))
    }
}

/// Remove a directory tree.
///
/// The containers write files into the data directory as other users
/// (root, or the search engine UID), which an unprivileged
/// remove_dir_all can't always delete. On a permission error, fall
/// back to deleting the contents with a container, which runs with
/// the same privileges that created the files.
fn remove_directory(context: &Context, directory: &Path) -> Result<()> {
    info!("Removing {}", directory.display());
    let err = match std::fs::remove_dir_all(directory) {
        Ok(()) => return Ok(()),
        Err(err) => err,
    };
    if err.kind() != std::io::ErrorKind::PermissionDenied {
        bail!("Failed to remove {}: {}", directory.display(), err);
    }

    info!("Permission denied, removing container-created files with a container");
    remove_contents_with_container(context, directory)
        .with_context(|| format!("Failed to remove {} with a container", directory.display()))?;
    std::fs::remove_dir_all(directory)
        .with_context(|| format!("Failed to remove {}", directory.display()))
}

/// Delete the contents of a directory from inside a container,
/// running as root in the container regardless of the image's
/// default user.
fn remove_contents_with_container(context: &Context, directory: &Path) -> Result<()> {
    let image = known_images(context)
        .into_iter()
        .find(|image| context.manager.has_image(image))
        .ok_or_else(|| {
            anyhow!(
                "No container image available, remove the directory manually or re-run with sudo"
            )
        })?;

    let output = context
        .manager
        .command()
        .args(["run", "--rm", "--user=0", "--entrypoint", "/bin/sh"])
        .arg(format!(
            "--volume={}",
            context.manager.bind_mount(directory, "/target")
        ))
        .arg(image)
        .args(["-c", "rm -rf /target/* /target/.[!.]* /target/..?*"])
        .output()?;
    if !output.status.success() {
        bail!(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(())
}

/// This instance's containers that currently exist, running or not.
fn existing_containers(context: &Context) -> Vec<String> {
    let mut names = vec![
        crate::suricata::container_name(context),
        crate::evebox::server::container_name(context),
        crate::evebox::agent::container_name(context),
    ];
    for engine in [SearchEngine::Elasticsearch, SearchEngine::OpenSearch] {
        names.push(elastic::container_name_for(context, engine));
    }
    names.retain(|name| context.manager.container_exists(name));
    names
}

/// The container images EveCtl may have pulled.
fn known_images(context: &Context) -> Vec<String> {
    vec![
        context.image_name(Container::Suricata),
        context.image_name(Container::EveBox),
        elastic::ELASTICSEARCH_IMAGE.to_string(),
        elastic::OPENSEARCH_IMAGE.to_string(),
    ]
}

/// The known images that are present.
fn existing_images(context: &Context) -> Vec<String> {
    let mut images = known_images(context);
    images.retain(|image| context.manager.has_image(image));
    images
}
