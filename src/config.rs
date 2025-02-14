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
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ContainerConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub runtime: String,
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
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EveBoxServerConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub allow_remote: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub no_tls: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub no_auth: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub image: Option<String>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub elastic_index: Option<String>,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ElasticsearchConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub enabled: bool,
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
}

impl Config {
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
        let mut file = std::fs::File::create(&self.filename)?;
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
