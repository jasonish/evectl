// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::path::PathBuf;
use std::process::Command;

use crate::config::SearchEngine;
use crate::container::RESTART_POLICY_ARG;
use crate::prelude::*;

pub(crate) const ELASTICSEARCH_IMAGE: &str =
    "docker.elastic.co/elasticsearch/elasticsearch:8.19.19";
pub(crate) const OPENSEARCH_IMAGE: &str = "docker.io/opensearchproject/opensearch:3.7.0";

/// What differs between the supported search engines.
pub(crate) struct EngineSpec {
    pub(crate) image: &'static str,
    /// The program to run in the container.
    bin: &'static str,
    args: &'static [&'static str],
    /// Subdirectory of the data directory holding the engine's data.
    data_subdir: &'static str,
    /// Where the data directory is mounted in the container.
    mount_target: &'static str,
    /// Suffix of the container name.
    name_suffix: &'static str,
    /// Environment variable taking the JVM heap options, for engines
    /// that don't size the heap to the container memory limit.
    java_opts_env: Option<&'static str>,
}

const ELASTICSEARCH: EngineSpec = EngineSpec {
    image: ELASTICSEARCH_IMAGE,
    bin: "bin/elasticsearch",
    args: &[
        "-Expack.security.enabled=false",
        "-Ediscovery.type=single-node",
        "-Elogger.level=ERROR",
    ],
    data_subdir: "elastic",
    mount_target: "/usr/share/elasticsearch/data",
    name_suffix: "elastic",
    java_opts_env: None,
};

const OPENSEARCH: EngineSpec = EngineSpec {
    image: OPENSEARCH_IMAGE,
    bin: "bin/opensearch",
    args: &[
        "-Eplugins.security.disabled=true",
        "-Ediscovery.type=single-node",
        "-Elogger.level=ERROR",
    ],
    data_subdir: "opensearch",
    mount_target: "/usr/share/opensearch/data",
    name_suffix: "opensearch",
    // Unlike Elasticsearch, OpenSearch does not size its heap to the
    // container memory limit.
    java_opts_env: Some("OPENSEARCH_JAVA_OPTS"),
};

impl SearchEngine {
    pub(crate) fn spec(self) -> &'static EngineSpec {
        match self {
            SearchEngine::Elasticsearch => &ELASTICSEARCH,
            SearchEngine::OpenSearch => &OPENSEARCH,
        }
    }
}

pub(crate) fn engine(context: &Context) -> SearchEngine {
    context.config.elasticsearch.engine
}

pub(crate) fn docker_image(context: &Context) -> &'static str {
    engine(context).spec().image
}

pub(crate) fn container_name(context: &Context) -> String {
    container_name_for(context, engine(context))
}

pub(crate) fn container_name_for(context: &Context, engine: SearchEngine) -> String {
    format!(
        "{}-{}",
        context.container_prefix(),
        engine.spec().name_suffix
    )
}

pub(crate) fn existing_engines(context: &Context) -> Vec<SearchEngine> {
    SearchEngine::ALL
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
    context.data_dir().join(engine(context).spec().data_subdir)
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
    // Stop and remove the container names of both engines so switching
    // engines doesn't leave the previous one behind.
    for engine in SearchEngine::ALL {
        let name = container_name_for(context, engine);
        if context.manager.is_active(&name) {
            let _ = context.manager.stop(&name, None);
        }
        context.manager.quiet_rm(&name);
    }
}

pub(crate) fn build_docker_command(context: &Context, detached: bool) -> Command {
    let spec = engine(context).spec();
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--name");
    command.arg(container_name(context));
    if detached {
        command.arg("--detach");
        command.arg(RESTART_POLICY_ARG);
    } else {
        command.arg("--rm");
    }
    // Without a memory limit Elasticsearch sizes its heap to half of
    // all host memory, which on a large host can be OOM killed while
    // pre-allocating the heap on startup. With a limit, the heap is
    // sized to half the limit.
    command.arg(format!(
        "--memory={}g",
        context.config.elasticsearch.memory_gb()
    ));
    // Engines that don't size their heap to the container memory
    // limit get it explicitly sized to half the limit.
    if let Some(java_opts_env) = spec.java_opts_env {
        command.arg("--env");
        command.arg(format!(
            "{java_opts_env}=-Xms{0}m -Xmx{0}m",
            context.config.elasticsearch.memory_gb() * 1024 / 2
        ));
    }
    // The images run as UID 1000, which under Podman, particularly
    // rootless, may be mapped to a subordinate ID the host side can't
    // chown to, so have Podman fix up the data directory ownership
    // itself with the ":U" volume option.
    let volume_opts = if context.manager.is_podman() {
        &["U"][..]
    } else {
        &[]
    };
    command.arg("-v");
    command.arg(context.manager.bind_mount_with_options(
        &host_data_dir(context),
        spec.mount_target,
        volume_opts,
    ));
    command.arg(spec.image);
    command.arg(spec.bin);
    command.args(spec.args);
    command
}

/// Start the search engine detached.
pub(crate) fn start_elasticsearch(context: &Context) -> Result<()> {
    crate::container::start_detached(
        context,
        &container_name(context),
        engine(context).name(),
        || {
            stop_elasticsearch(context);
            create_data_dir(context)?;
            Ok(build_docker_command(context, true))
        },
    )
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::container::command_args;
    use crate::context::testing::docker_context;

    #[test]
    fn engine_specs_select_image_names_and_mounts() {
        let mut config = Config::default();
        config.evebox_server.enabled = true;
        config.elasticsearch.enabled = true;
        let (_root, mut context) = docker_context(config);

        assert_eq!(docker_image(&context), ELASTICSEARCH_IMAGE);
        assert!(container_name(&context).ends_with("-elastic"));
        assert_eq!(host_data_dir(&context), context.data_dir().join("elastic"));
        let args = command_args(&build_docker_command(&context, true));
        assert!(
            args.iter()
                .any(|a| a.ends_with(":/usr/share/elasticsearch/data"))
        );
        assert!(args.contains(&"bin/elasticsearch".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("OPENSEARCH_JAVA_OPTS=")));

        context.config.elasticsearch.engine = SearchEngine::OpenSearch;
        assert_eq!(docker_image(&context), OPENSEARCH_IMAGE);
        assert!(container_name(&context).ends_with("-opensearch"));
        assert_eq!(
            host_data_dir(&context),
            context.data_dir().join("opensearch")
        );
        let args = command_args(&build_docker_command(&context, true));
        assert!(
            args.iter()
                .any(|a| a.ends_with(":/usr/share/opensearch/data"))
        );
        assert!(args.contains(&"bin/opensearch".to_string()));
        assert!(args.contains(&"OPENSEARCH_JAVA_OPTS=-Xms1024m -Xmx1024m".to_string()));
    }
}
