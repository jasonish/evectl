// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

pub(crate) fn container_name(context: &Context) -> String {
    let parent = context.root.file_name().unwrap().to_string_lossy();
    format!("{}-evectl-suricata", parent)
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
        context.data_dir().join("suricata").join("run"),
    ];

    for dir in dirs {
        info!("Creating directory: {}", dir.display());
        std::fs::create_dir_all(&dir)?;
    }

    Ok(())
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
    if path.exists()
        && let Err(err) = std::fs::remove_file(&path)
    {
        warn!("Failed to remove {}: {}", path.display(), err);
    }
}
