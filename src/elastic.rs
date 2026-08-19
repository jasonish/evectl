// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::path::PathBuf;
use std::process::Command;

use crate::config::SearchEngine;
use crate::prelude::*;

const ELASTICSEARCH_IMAGE: &str = "docker.elastic.co/elasticsearch/elasticsearch:8.19.19";
const OPENSEARCH_IMAGE: &str = "docker.io/opensearchproject/opensearch:3.7.0";

/// Default container memory limit in gigabytes.
pub(crate) const DEFAULT_MEMORY_GB: u32 = 2;

/// The configured container memory limit in gigabytes.
pub(crate) fn memory_gb(context: &Context) -> u32 {
    context
        .config
        .elasticsearch
        .memory
        .unwrap_or(DEFAULT_MEMORY_GB)
}

const ELASTICSEARCH_BIN: &str = "bin/elasticsearch";
const OPENSEARCH_BIN: &str = "bin/opensearch";

const ELASTICSEARCH_ARGS: &[&str] = &[
    "-Expack.security.enabled=false",
    "-Ediscovery.type=single-node",
    "-Elogger.level=ERROR",
];

const OPENSEARCH_ARGS: &[&str] = &[
    "-Eplugins.security.disabled=true",
    "-Ediscovery.type=single-node",
    "-Elogger.level=ERROR",
];

pub(crate) fn engine(context: &Context) -> SearchEngine {
    context.config.elasticsearch.engine
}

pub(crate) fn docker_image(context: &Context) -> &'static str {
    match engine(context) {
        SearchEngine::Elasticsearch => ELASTICSEARCH_IMAGE,
        SearchEngine::OpenSearch => OPENSEARCH_IMAGE,
    }
}

pub(crate) fn container_name(context: &Context) -> String {
    container_name_for(context, engine(context))
}

fn container_name_for(context: &Context, engine: SearchEngine) -> String {
    let root = context.root.file_name().unwrap().to_string_lossy();
    match engine {
        SearchEngine::Elasticsearch => format!("{}-evectl-elastic", root),
        SearchEngine::OpenSearch => format!("{}-evectl-opensearch", root),
    }
}

pub(crate) fn existing_engines(context: &Context) -> Vec<SearchEngine> {
    [SearchEngine::Elasticsearch, SearchEngine::OpenSearch]
        .into_iter()
        .filter(|engine| {
            context
                .manager
                .container_exists(&container_name_for(context, *engine))
        })
        .collect()
}

/// The host directory holding the search engine data.
///
/// Each engine gets its own directory as their data formats are not
/// compatible with each other.
pub(crate) fn host_data_dir(context: &Context) -> PathBuf {
    let dir = match engine(context) {
        SearchEngine::Elasticsearch => "elastic",
        SearchEngine::OpenSearch => "opensearch",
    };
    context.data_dir().join(dir)
}

/// The UID both the Elasticsearch and OpenSearch images run as.
#[cfg(unix)]
const CONTAINER_UID: u32 = 1000;

/// Create the host data directory, making sure the container user can
/// write to it.
pub(crate) fn create_data_dir(context: &Context) -> Result<PathBuf> {
    let dir = host_data_dir(context);
    std::fs::create_dir_all(&dir)?;

    // The images run as UID 1000 which won't be able to write to a
    // directory created by another user, typically root. Podman is
    // handled with the ":U" volume option.
    #[cfg(unix)]
    if !context.manager.is_podman() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if std::fs::metadata(&dir)?.uid() != CONTAINER_UID {
            // Hand the directory over to the container UID, and if
            // that fails (not running as root), open up the
            // permissions instead.
            if std::os::unix::fs::chown(&dir, Some(CONTAINER_UID), None).is_err() {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))?;
            }
        }
    }

    Ok(dir)
}

pub(crate) fn stop_elasticsearch(context: &Context) {
    // Stop the container names of both engines so switching engines
    // doesn't leave the previous one running.
    for engine in [SearchEngine::Elasticsearch, SearchEngine::OpenSearch] {
        let _ = context
            .manager
            .stop(&container_name_for(context, engine), None);
    }
}

pub(crate) fn build_docker_command(context: &Context, dargs: &[&str]) -> Command {
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--name");
    command.arg(container_name(context));
    command.arg("--rm");
    // Without a memory limit Elasticsearch sizes its heap to half of
    // all host memory, which on a large host can be OOM killed while
    // pre-allocating the heap on startup. With a limit, the heap is
    // sized to half the limit.
    command.arg(format!("--memory={}g", memory_gb(context)));
    // The images run as UID 1000, which under Podman, particularly
    // rootless, may be mapped to a subordinate ID the host side can't
    // chown to, so have Podman fix up the data directory ownership
    // itself with the ":U" volume option.
    let volume_opts = if context.manager.is_podman() {
        ":U"
    } else {
        ""
    };
    match engine(context) {
        SearchEngine::Elasticsearch => {
            command.arg("-v");
            command.arg(format!(
                "{}:/usr/share/elasticsearch/data{}",
                host_data_dir(context).display(),
                volume_opts
            ));
        }
        SearchEngine::OpenSearch => {
            // Unlike Elasticsearch, OpenSearch does not size its heap
            // to the container memory limit, so explicitly size it to
            // half the limit.
            command.arg("--env");
            command.arg(format!(
                "OPENSEARCH_JAVA_OPTS=-Xms{0}m -Xmx{0}m",
                memory_gb(context) * 1024 / 2
            ));
            command.arg("-v");
            command.arg(format!(
                "{}:/usr/share/opensearch/data{}",
                host_data_dir(context).display(),
                volume_opts
            ));
        }
    }
    if !dargs.is_empty() {
        command.args(dargs);
    }
    command.arg(docker_image(context));
    match engine(context) {
        SearchEngine::Elasticsearch => {
            command.arg(ELASTICSEARCH_BIN);
            command.args(ELASTICSEARCH_ARGS);
        }
        SearchEngine::OpenSearch => {
            command.arg(OPENSEARCH_BIN);
            command.args(OPENSEARCH_ARGS);
        }
    }
    command
}

/// Start the search engine detached.
pub(crate) fn start_elasticsearch(context: &Context) -> Result<()> {
    stop_elasticsearch(context);
    create_data_dir(context)?;
    context.manager.quiet_rm(&container_name(context));

    let mut command = build_docker_command(context, &["--detach"]);

    let output = command.output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to start {}: {}",
            engine(context).name(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}
