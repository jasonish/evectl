// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The `update` command: update EveCtl itself, then the container
//! images. A self-update re-executes the new binary to finish the
//! container updates.

use std::path::{Path, PathBuf};
use std::process;

use semver::Version;

use crate::container::Container;
use crate::prelude::*;
use crate::{elastic, housekeeper, selfupdate, services, suricata};

/// The runtime flags to pass to a new EveCtl binary when continuing
/// an update after a self-update.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct UpdateContinuationArgs {
    pub(crate) podman: bool,
    pub(crate) no_root: bool,
    pub(crate) data_directory: Option<PathBuf>,
    pub(crate) verbose: u8,
}

impl UpdateContinuationArgs {
    #[cfg(not(windows))]
    pub(crate) fn new(
        manager: crate::container::ContainerManager,
        args: &crate::cli::Args,
    ) -> Self {
        Self {
            podman: manager.is_podman(),
            no_root: args.no_root,
            data_directory: args.data_directory.clone(),
            verbose: args.verbose,
        }
    }

    fn to_args(&self, return_to_menu: bool) -> Vec<String> {
        let mut args = vec![];
        if self.podman {
            args.push("--podman".to_string());
        }
        if self.no_root {
            args.push("--no-root".to_string());
        }
        if let Some(directory) = &self.data_directory {
            args.push("--data-directory".to_string());
            args.push(directory.to_string_lossy().to_string());
        }
        for _ in 0..self.verbose {
            args.push("-v".to_string());
        }
        args.push("update".to_string());
        args.push("--containers-only".to_string());
        if return_to_menu {
            args.push("--return-to-menu".to_string());
        }
        args
    }
}

pub(crate) fn update(
    context: &Context,
    update_continuation_args: &UpdateContinuationArgs,
    containers_only: bool,
    return_to_menu: bool,
) -> bool {
    if containers_only {
        return update_containers(context, return_to_menu);
    }

    match selfupdate::self_update() {
        Ok(selfupdate::SelfUpdate::Unchanged) => update_containers(context, return_to_menu),
        Ok(selfupdate::SelfUpdate::Updated(current_exe)) => {
            std::process::exit(continue_update_with_new_binary(
                &current_exe,
                update_continuation_args,
                return_to_menu,
            ));
        }
        Err(err) => {
            error!("Failed to update EveCtl: {err}");
            info!("Continuing with container updates");
            update_containers(context, return_to_menu);
            false
        }
    }
}

/// Offer to restart Suricata after an update changed its version.
fn prompt_restart_for_updated_suricata(context: &Context, running: &Version, image: &Version) {
    let message = format!("Suricata updated from {running} to {image}, restart now?");
    if let Ok(Some(true)) = inquire::Confirm::new(&message)
        .with_default(true)
        .prompt_skippable()
    {
        services::restart(context);
    }
}

/// If Suricata is running and its version differs from the version
/// in the configured image, return the running and image versions.
fn suricata_update_pending(context: &Context) -> Option<(Version, Version)> {
    if !context.config.suricata.enabled
        || !context
            .manager
            .is_running(&suricata::container_name(context))
    {
        return None;
    }
    let running = match suricata::running_version(context) {
        Ok(Some(version)) => version,
        Ok(None) => return None,
        Err(err) => {
            debug!("Failed to determine the running Suricata version: {err}");
            return None;
        }
    };
    let image = match suricata::image_version(context) {
        Ok(Some(version)) => version,
        Ok(None) => return None,
        Err(err) => {
            debug!("Failed to determine the Suricata image version: {err}");
            return None;
        }
    };
    if running != image {
        Some((running, image))
    } else {
        None
    }
}

/// Pull the container images. If the running Suricata version differs
/// from the image afterwards, offer a restart when interactive,
/// otherwise log that a restart is required.
fn update_containers(context: &Context, interactive: bool) -> bool {
    let mut ok = true;
    for image in [
        context.image_name(Container::Suricata),
        context.image_name(Container::EveBox),
    ] {
        if let Err(err) = context.manager.pull(&image) {
            error!("Failed to pull {image}: {err}");
            ok = false;
        }
    }
    if context.config.elasticsearch_enabled() {
        let image = elastic::docker_image(context);
        if let Err(err) = context.manager.pull(image) {
            error!("Failed to pull {image}: {err}");
            ok = false;
        }
    }
    if housekeeper::enabled(context) {
        info!("Housekeeper will use the updated Suricata image on the next evectl start/restart");
    }
    if let Some((running, image)) = suricata_update_pending(context) {
        if interactive {
            prompt_restart_for_updated_suricata(context, &running, &image);
        } else {
            info!("Suricata updated from {running} to {image}, restart required");
        }
    }
    ok
}

fn continue_update_with_new_binary(
    current_exe: &Path,
    update_continuation_args: &UpdateContinuationArgs,
    return_to_menu: bool,
) -> i32 {
    let args = update_continuation_args.to_args(return_to_menu);
    info!("Continuing update with {}", current_exe.display());
    let status = process::Command::new(current_exe).args(&args).status();
    match status {
        Ok(status) if status.success() => 0,
        Ok(status) => status.code().unwrap_or(1),
        Err(err) => {
            error!("Failed to continue update with new EveCtl: {err}");
            1
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::cli::Args;
    use crate::container::ContainerManager;
    use clap::Parser;

    #[test]
    fn update_continuation_args_preserve_runtime_flags() {
        let args = Args::try_parse_from([
            "evectl",
            "--no-root",
            "-vv",
            "-D",
            "/var/lib/evectl-test",
            "update",
        ])
        .expect("parse args");
        let manager = ContainerManager::Podman;

        assert_eq!(
            UpdateContinuationArgs::new(manager, &args),
            UpdateContinuationArgs {
                podman: true,
                no_root: true,
                data_directory: Some(PathBuf::from("/var/lib/evectl-test")),
                verbose: 2,
            }
        );
        assert_eq!(
            UpdateContinuationArgs::new(manager, &args).to_args(false),
            vec![
                "--podman",
                "--no-root",
                "--data-directory",
                "/var/lib/evectl-test",
                "-v",
                "-v",
                "update",
                "--containers-only",
            ]
        );
    }

    #[test]
    fn update_continuation_args_omit_default_flags() {
        let args = UpdateContinuationArgs {
            podman: false,
            no_root: false,
            data_directory: None,
            verbose: 0,
        };

        assert_eq!(args.to_args(false), vec!["update", "--containers-only"]);
        assert_eq!(
            args.to_args(true),
            vec!["update", "--containers-only", "--return-to-menu"]
        );
    }
}
