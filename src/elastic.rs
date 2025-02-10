// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::process::Command;

use crate::prelude::*;

const DOCKER_IMAGE: &str = "docker.elastic.co/elasticsearch/elasticsearch:8.17.1";

const BIN: &str = "bin/elasticsearch";

const ARGS: &[&str] = &[
    "-Expack.security.enabled=false",
    "-Ediscovery.type=single-node",
    "-Elogger.level=ERROR",
];

pub(crate) fn container_name(context: &Context) -> String {
    let root = context.root.file_name().unwrap().to_string_lossy();
    format!("{}-evectl-elastic", root)
}

pub(crate) fn stop_elasticsearch(context: &Context) {
    let _ = context.manager.stop(&container_name(context), None);
}

pub(crate) fn build_docker_command(context: &Context, dargs: &[&str]) -> Command {
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--name");
    command.arg(container_name(context));
    command.arg("--rm");
    command.arg("-v");
    command.arg(format!(
        "{}/elastic:/usr/share/elasticsearch/data",
        context.data_dir().display()
    ));
    if !dargs.is_empty() {
        command.args(dargs);
    }
    command.arg(DOCKER_IMAGE);
    command.arg(BIN);
    command.args(ARGS);
    command
}

/// Start Elasticsearch detached.
pub(crate) fn start_elasticsearch(context: &Context) -> Result<()> {
    stop_elasticsearch(context);
    context.manager.quiet_rm(&container_name(context));

    let mut command = build_docker_command(context, &["--detach"]);

    let output = command.output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to start elasticsearch: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}
