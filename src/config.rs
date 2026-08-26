// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Config {
    #[serde(skip)]
    filename: PathBuf,

    #[serde(default, skip_serializing_if = "is_default")]
    pub suricata: SuricataConfig,

    #[serde(default, skip_serializing_if = "is_default")]
    pub evebox_server: EveBoxServerConfig,

    #[serde(default, skip_serializing_if = "is_default")]
    pub evebox_agent: EveBoxAgentConfig,

    #[serde(default, skip_serializing_if = "is_default")]
    pub elasticsearch: ElasticsearchConfig,

    #[serde(default, skip_serializing_if = "is_default")]
    pub fpc: FpcConfig,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct SuricataConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub interfaces: Vec<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub image: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub bpf: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub sensor_name: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub eve_output: EveOutput,
}

/// Full packet capture configuration. When enabled, Suricata writes a
/// rotating pcap spool that is served through the EveBox web UI, either
/// directly by the local EveBox server or by the local EveBox agent on
/// behalf of a remote server. Requires Suricata and one of the two; not
/// supported on Windows.
#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FpcConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub enabled: bool,

    /// Maximum total number of pcap files to retain across all
    /// capture threads.
    #[serde(default, skip_serializing_if = "is_default")]
    pub max_files: Option<u32>,
}

impl FpcConfig {
    pub(crate) const DEFAULT_MAX_FILES: u32 = 100;
    pub(crate) const FILE_SIZE: &'static str = "256mb";

    pub(crate) fn max_files(&self) -> u32 {
        self.max_files.unwrap_or(Self::DEFAULT_MAX_FILES)
    }

    /// Suricata enforces `max-files` per capture thread in multi
    /// mode, so divide the global cap by the thread count (at least
    /// one file per thread).
    pub(crate) fn max_files_per_thread(&self, threads: usize) -> u32 {
        (self.max_files() / threads.max(1) as u32).max(1)
    }

    /// Number of capture threads Suricata will use with
    /// `threads: auto`, assumed to be the number of host CPUs.
    pub(crate) fn capture_threads() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }

    /// Approximate maximum disk usage of the pcap spool in GB, taking
    /// the per-thread rounding into account.
    pub(crate) fn disk_usage_gb(&self) -> u64 {
        let threads = Self::capture_threads();
        self.max_files_per_thread(threads) as u64 * threads as u64 * 256 / 1024
    }
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, Copy, Eq, PartialEq)]
pub(crate) enum EveOutput {
    #[default]
    #[serde(rename = "unix-stream")]
    UnixStream,
    #[serde(rename = "file")]
    File,
}

impl EveOutput {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::UnixStream => "Unix stream",
            Self::File => "File",
        }
    }
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EveBoxServerConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub allow_remote: bool,

    /// Bind value for EveBox server publishing.
    ///
    /// This may be either:
    /// - an interface name (e.g., "eth0"), which resolves to the first IPv4
    ///   address on that interface, or
    /// - an explicit IP address (e.g., "192.168.1.10").
    ///
    /// Only used when `allow_remote` is true.
    #[serde(
        default,
        skip_serializing_if = "is_default",
        alias = "bind-interface",
        alias = "bind_interface"
    )]
    pub bind_address: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub no_tls: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub no_auth: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub image: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub use_external_elasticsearch: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub elasticsearch_client: ElasticsearchClientConfig,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ElasticsearchClientConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub url: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub index: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub username: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub password: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub disable_certificate_validation: bool,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ElasticsearchConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub enabled: bool,

    /// Which search engine to run. Defaults to Elasticsearch as
    /// configurations that predate this option were Elasticsearch
    /// only.
    #[serde(default, skip_serializing_if = "is_default")]
    pub engine: SearchEngine,

    /// Container memory limit in gigabytes. The search engine sizes
    /// its heap to half of this. None means the default of 2.
    #[serde(default, skip_serializing_if = "is_default")]
    pub memory: Option<u32>,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SearchEngine {
    #[default]
    #[serde(rename = "elasticsearch")]
    Elasticsearch,
    #[serde(rename = "opensearch")]
    OpenSearch,
}

impl SearchEngine {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            SearchEngine::Elasticsearch => "Elasticsearch",
            SearchEngine::OpenSearch => "OpenSearch",
        }
    }
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EveBoxAgentConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub server: String,

    #[serde(default, skip_serializing_if = "is_default")]
    pub disable_certificate_validation: bool,

    /// Identifier the agent presents to the server, stamped on each
    /// event and claimed on the packet capture channel. EveBox
    /// defaults to the hostname when unset. Full packet capture
    /// requires it to match the name of an agent key on the server.
    #[serde(default, skip_serializing_if = "is_default")]
    pub agent_id: Option<String>,

    /// Agent key issued by the EveBox server (`evebox config agents
    /// add <agent-id>`), used to authenticate the packet capture
    /// channel.
    #[serde(default, skip_serializing_if = "is_default")]
    pub key: Option<String>,
}

impl Config {
    /// True if the managed search engine (Elasticsearch/OpenSearch)
    /// should be running. The engine only exists as a datastore for
    /// the EveBox server, so it is implicitly disabled when the
    /// server is disabled or using an external datastore.
    pub(crate) fn elasticsearch_enabled(&self) -> bool {
        self.evebox_server.enabled
            && !self.evebox_server.use_external_elasticsearch
            && self.elasticsearch.enabled
    }

    pub(crate) fn default_with_filename(filename: &Path) -> Self {
        Self {
            filename: filename.to_path_buf(),
            ..Default::default()
        }
    }

    pub(crate) fn from_file(filename: &PathBuf) -> Result<Self> {
        let buf = Self::read_file(filename)?;
        let mut config = Self::parse_toml(&buf)?;
        config.filename = filename.clone();
        Ok(config)
    }

    pub(crate) fn save(&self) -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o640);
        }
        let mut file = options.open(&self.filename)?;
        let config = toml::to_string(self)?;
        file.write_all(config.as_bytes())?;

        Ok(())
    }

    fn read_file(filename: &PathBuf) -> Result<String> {
        let mut file = std::fs::File::open(filename)?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        Ok(buffer)
    }

    fn parse_toml(buf: &str) -> Result<Config> {
        Ok(toml::from_str(buf)?)
    }
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_roundtrip() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.suricata.interfaces = vec!["br0".to_string()];
        config.evebox_server.enabled = true;
        config.evebox_server.no_tls = true;
        config.evebox_server.bind_address = Some("192.168.1.10".to_string());
        config.elasticsearch.engine = SearchEngine::OpenSearch;
        config.elasticsearch.memory = Some(4);
        config.evebox_agent.agent_id = Some("sensor-1".to_string());
        config.evebox_agent.key = Some("secret".to_string());
        config.fpc.enabled = true;
        config.fpc.max_files = Some(20);

        let toml = toml::to_string(&config).unwrap();
        let parsed = Config::parse_toml(&toml).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_parse_search_engine() {
        // Configurations from before the engine option default to
        // Elasticsearch.
        let config = Config::parse_toml(
            r#"
            [elasticsearch]
            enabled = true
            "#,
        )
        .unwrap();
        assert_eq!(config.elasticsearch.engine, SearchEngine::Elasticsearch);

        let config = Config::parse_toml(
            r#"
            [elasticsearch]
            enabled = true
            engine = "opensearch"
            "#,
        )
        .unwrap();
        assert_eq!(config.elasticsearch.engine, SearchEngine::OpenSearch);
    }

    #[test]
    fn test_elasticsearch_enabled_requires_server() {
        let mut config = Config::default();
        config.elasticsearch.enabled = true;
        assert!(!config.elasticsearch_enabled());

        config.evebox_server.enabled = true;
        assert!(config.elasticsearch_enabled());

        config.evebox_server.use_external_elasticsearch = true;
        assert!(!config.elasticsearch_enabled());
    }

    #[test]
    fn eve_output_defaults_to_unix_stream_with_file_opt_out() {
        let default = Config::parse_toml("[suricata]\nenabled = true\n").unwrap();
        assert_eq!(default.suricata.eve_output, EveOutput::UnixStream);

        let file = Config::parse_toml(
            r#"
            [suricata]
            eve-output = "file"
            "#,
        )
        .unwrap();
        assert_eq!(file.suricata.eve_output, EveOutput::File);
        assert!(
            toml::to_string(&file)
                .unwrap()
                .contains("eve-output = \"file\"")
        );
    }

    #[test]
    fn test_parse_config() {
        let config = Config::parse_toml(
            r#"
            [suricata]
            enabled = true
            interfaces = ["br0"]

            [evebox-server]
            enabled = true
            no-tls = true
            no-auth = true
            "#,
        )
        .unwrap();
        assert!(config.suricata.enabled);
        assert_eq!(config.suricata.interfaces, vec!["br0".to_string()]);
        assert!(config.evebox_server.no_tls);
    }
}

#[cfg(test)]
mod fpc_tests {
    use super::FpcConfig;

    #[test]
    fn max_files_is_divided_across_threads() {
        let fpc = FpcConfig {
            enabled: true,
            max_files: Some(100),
        };
        assert_eq!(fpc.max_files_per_thread(1), 100);
        assert_eq!(fpc.max_files_per_thread(4), 25);
        assert_eq!(fpc.max_files_per_thread(16), 6);
        // Never below one file per thread.
        assert_eq!(fpc.max_files_per_thread(1000), 1);
        assert_eq!(fpc.max_files_per_thread(0), 100);
    }
}
