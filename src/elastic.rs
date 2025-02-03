// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::process::Command;

use crate::prelude::*;

const DOCKER_IMAGE: &str = "docker.elastic.co/elasticsearch/elasticsearch:8.17.1";
pub(crate) const ELASTICSEARCH_CONTAINER_NAME: &str = "evectl-elastic";
const BIN: &str = "bin/elasticsearch";
const ARGS: &[&str] = &[
    "-Expack.security.enabled=false",
    "-Ediscovery.type=single-node",
    "-Elogger.level=ERROR",
];

pub(crate) fn stop_elasticsearch(context: &Context) {
    let _ = context.manager.stop(ELASTICSEARCH_CONTAINER_NAME, None);
}

pub(crate) fn build_docker_command(context: &Context, dargs: &[&str]) -> Command {
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--name");
    command.arg(ELASTICSEARCH_CONTAINER_NAME);
    command.arg("--rm");
    command.arg("-v");
    command.arg(format!(
        "{}/elastic:/usr/share/elasticsearch/data",
        context.data_directory.display()
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
    context.manager.quiet_rm(ELASTICSEARCH_CONTAINER_NAME);

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
