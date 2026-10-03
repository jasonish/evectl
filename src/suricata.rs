// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

pub(crate) mod configuration;

use crate::container::{CommandExt, SuricataContainer};
use crate::prelude::*;

pub(crate) fn container_name(context: &Context) -> String {
    format!("{}-suricata", context.container_prefix())
}

pub(crate) fn mkdirs(context: &Context) -> Result<()> {
    let dirs = vec![
        context.config_dir().join("suricata").join("lib"),
        context
            .config_dir()
            .join("suricata")
            .join("lib")
            .join("rules"),
        context
            .config_dir()
            .join("suricata")
            .join("lib")
            .join("update"),
        context
            .config_dir()
            .join("suricata")
            .join("lib")
            .join("update")
            .join("cache"),
        context.data_dir().join("suricata").join("log"),
        context.data_dir().join("suricata").join("log").join("pcap"),
        context.data_dir().join("suricata").join("run"),
    ];

    for dir in dirs {
        info!("Creating directory: {}", dir.display());
        std::fs::create_dir_all(&dir)?;
    }

    Ok(())
}

/// Host path of the extracted files (file-store) directory, bind
/// mounted into the Suricata container as /var/log/suricata/filestore.
/// Created by Suricata when file extraction is enabled.
pub(crate) fn filestore_dir(context: &Context) -> std::path::PathBuf {
    context
        .data_dir()
        .join("suricata")
        .join("log")
        .join("filestore")
}

/// Remove the Suricata engine log (suricata.log). Done on each start
/// of Suricata to keep it from growing unbounded, as log rotation is
/// no longer used.
pub(crate) fn remove_engine_log(context: &Context) {
    let path = context
        .data_dir()
        .join("suricata")
        .join("log")
        .join("suricata.log");
    if !path.exists() {
        return;
    }

    // The log is created by Suricata in the container and may not be
    // removable by the host user. Use a short-lived Suricata container so
    // the bind-mounted file is removed with the same container privileges.
    let container = SuricataContainer::new(context.clone());
    if let Err(err) = container
        .run()
        .rm()
        .args(&["rm", "-f", "/var/log/suricata/suricata.log"])
        .build()
        .status_ok()
    {
        warn!("Failed to remove {}: {}", path.display(), err);
    }
}
