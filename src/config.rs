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

    #[serde(default, skip_serializing_if = "is_default")]
    pub file_extraction: FileExtractionConfig,
}

/// Suricata file extraction (file-store) configuration. When enabled,
/// files seen in supported protocols (HTTP, SMTP, FTP, SMB, NFS) are
/// written to the Suricata log directory, deduplicated by SHA256. Not
/// supported on Windows.
#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FileExtractionConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub enabled: bool,

    /// file-store `force-filestore`: store all files, or when false
    /// (Suricata's default) only files matched by rules using the
    /// `filestore` keyword.
    #[serde(default, skip_serializing_if = "is_default")]
    pub force_filestore: bool,

    /// How much of a file to extract (e.g. "4mb"); larger files are
    /// stored truncated. Suricata limits are raised to this size, never
    /// lowered.
    #[serde(default, skip_serializing_if = "is_default")]
    pub max_size: Option<String>,

    /// Stored files older than this many days are deleted. 0 keeps
    /// files forever.
    #[serde(default, skip_serializing_if = "is_default")]
    pub max_age_days: Option<u32>,
}

impl FileExtractionConfig {
    pub(crate) const DEFAULT_MAX_SIZE: &'static str = "4mb";
    pub(crate) const DEFAULT_MAX_AGE_DAYS: u32 = 7;

    pub(crate) fn max_size(&self) -> &str {
        self.max_size.as_deref().unwrap_or(Self::DEFAULT_MAX_SIZE)
    }

    /// The max extract size in bytes. Falls back to the default if the
    /// configured value is invalid (e.g. hand edited).
    pub(crate) fn max_size_bytes(&self) -> u64 {
        Some(self.max_size())
            .filter(|s| Self::is_valid_size(s))
            .and_then(Self::parse_size)
            .or_else(|| Self::parse_size(Self::DEFAULT_MAX_SIZE))
            .unwrap_or_default()
    }

    pub(crate) fn max_age_days(&self) -> u32 {
        self.max_age_days.unwrap_or(Self::DEFAULT_MAX_AGE_DAYS)
    }

    /// Parse a Suricata size like "4mb", "1 MiB" or "4096" into bytes.
    /// Suricata units are binary.
    pub(crate) fn parse_size(s: &str) -> Option<u64> {
        let s = s.trim();
        let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (number, unit) = s.split_at(digits);
        let number: u64 = number.parse().ok()?;
        let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
            "" => 1,
            "kb" | "kib" => 1024,
            "mb" | "mib" => 1024 * 1024,
            "gb" | "gib" => 1024 * 1024 * 1024,
            _ => return None,
        };
        number.checked_mul(multiplier)
    }

    /// A valid max extract size is non-zero and fits Suricata's 32 bit
    /// size settings.
    pub(crate) fn is_valid_size(s: &str) -> bool {
        Self::parse_size(s).is_some_and(|size| size > 0 && size <= u64::from(u32::MAX))
    }
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
    /// capture threads. Suricata enforces the limit per thread, so
    /// the effective total is rounded down to a multiple of the
    /// thread count, with a minimum of one file per thread.
    #[serde(default, skip_serializing_if = "is_default")]
    pub max_files: Option<u32>,
}

impl FpcConfig {
    pub(crate) const DEFAULT_MAX_FILES: u32 = 100;
    pub(crate) const FILE_SIZE: &'static str = "256mb";
    const FILE_SIZE_MB: u64 = 256;

    pub(crate) fn max_files(&self) -> u32 {
        self.max_files.unwrap_or(Self::DEFAULT_MAX_FILES)
    }

    /// Suricata enforces `max-files` per capture thread in multi
    /// mode, so divide the global cap by the thread count (at least
    /// one file per thread).
    pub(crate) fn max_files_per_thread(&self, threads: usize) -> u32 {
        (self.max_files() / threads.max(1) as u32).max(1)
    }

    /// The total number of files Suricata will actually retain
    /// across `threads` capture threads.
    pub(crate) fn effective_max_files_for(&self, threads: usize) -> u32 {
        self.max_files_per_thread(threads) * threads.max(1) as u32
    }

    pub(crate) fn effective_max_files(&self) -> u32 {
        self.effective_max_files_for(Self::capture_threads())
    }

    /// Number of capture threads Suricata will use with
    /// `threads: auto`: one per online CPU, regardless of any
    /// affinity or quota applied to EveCtl itself.
    pub(crate) fn capture_threads() -> usize {
        evectl::system::online_cpus()
    }

    /// Approximate maximum disk usage of the pcap spool with
    /// `threads` capture threads, as a human readable size.
    pub(crate) fn disk_usage_for(&self, threads: usize) -> String {
        let mb = self.effective_max_files_for(threads) as u64 * Self::FILE_SIZE_MB;
        if mb >= 1024 {
            format!("{} GB", mb / 1024)
        } else {
            format!("{mb} MB")
        }
    }

    pub(crate) fn disk_usage(&self) -> String {
        self.disk_usage_for(Self::capture_threads())
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
        config.suricata.file_extraction.enabled = true;
        config.suricata.file_extraction.force_filestore = true;
        config.suricata.file_extraction.max_size = Some("16mb".to_string());
        config.suricata.file_extraction.max_age_days = Some(0);

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
mod file_extraction_tests {
    use super::*;

    #[test]
    fn defaults_to_disabled_and_is_not_serialized() {
        let config = Config::parse_toml("[suricata]\nenabled = true\n").unwrap();
        let fe = &config.suricata.file_extraction;
        assert_eq!(fe, &FileExtractionConfig::default());
        assert_eq!(fe.max_size(), "4mb");
        assert_eq!(fe.max_size_bytes(), 4 * 1024 * 1024);
        assert_eq!(fe.max_age_days(), 7);
        assert!(
            !toml::to_string(&config)
                .unwrap()
                .contains("file-extraction")
        );
    }

    #[test]
    fn parses_table() {
        let config = Config::parse_toml(
            r#"
            [suricata.file-extraction]
            enabled = true
            force-filestore = true
            max-size = "16mb"
            max-age-days = 30
            "#,
        )
        .unwrap();
        let fe = &config.suricata.file_extraction;
        assert!(fe.enabled);
        assert!(fe.force_filestore);
        assert_eq!(fe.max_size_bytes(), 16 * 1024 * 1024);
        assert_eq!(fe.max_age_days(), 30);
    }

    #[test]
    fn validates_sizes() {
        assert_eq!(FileExtractionConfig::parse_size("4096"), Some(4096));
        assert_eq!(FileExtractionConfig::parse_size("100 kb"), Some(102400));
        assert_eq!(FileExtractionConfig::parse_size("1 MiB"), Some(1024 * 1024));
        assert_eq!(
            FileExtractionConfig::parse_size(" 5MB "),
            Some(5 * 1024 * 1024)
        );
        assert_eq!(FileExtractionConfig::parse_size("mb"), None);
        assert_eq!(FileExtractionConfig::parse_size("5tb"), None);
        assert_eq!(FileExtractionConfig::parse_size("-5mb"), None);
        assert_eq!(FileExtractionConfig::parse_size("1.5mb"), None);

        assert!(FileExtractionConfig::is_valid_size("4mb"));
        assert!(FileExtractionConfig::is_valid_size("3gb"));
        assert!(!FileExtractionConfig::is_valid_size("0"));
        assert!(!FileExtractionConfig::is_valid_size("4gb"));
        assert!(!FileExtractionConfig::is_valid_size("lots"));

        // Invalid hand edited values fall back to the default.
        let fe = FileExtractionConfig {
            max_size: Some("lots".to_string()),
            ..Default::default()
        };
        assert_eq!(fe.max_size_bytes(), 4 * 1024 * 1024);
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

        // What Suricata really keeps, and what that costs.
        assert_eq!(fpc.effective_max_files_for(1), 100);
        assert_eq!(fpc.effective_max_files_for(4), 100);
        assert_eq!(fpc.effective_max_files_for(16), 96);
        assert_eq!(fpc.effective_max_files_for(1000), 1000);
        assert_eq!(fpc.disk_usage_for(1), "25 GB");
        assert_eq!(fpc.disk_usage_for(16), "24 GB");

        let small = FpcConfig {
            enabled: true,
            max_files: Some(2),
        };
        assert_eq!(small.effective_max_files_for(1), 2);
        assert_eq!(small.disk_usage_for(1), "512 MB");
        assert_eq!(small.effective_max_files_for(8), 8);
        assert_eq!(small.disk_usage_for(8), "2 GB");
    }
}
