// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
pub(crate) struct Config {
    #[serde(skip)]
    filename: PathBuf,

    pub suricata: SuricataConfig,

    #[serde(default)]
    pub evebox: EveBoxConfig,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
pub(crate) struct SuricataConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bpf: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EveBoxConfig {
    pub allow_remote: bool,
    pub no_tls: bool,
    pub no_auth: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

impl Default for EveBoxConfig {
    fn default() -> Self {
        Self {
            allow_remote: false,
            no_tls: true,
            no_auth: true,
            image: None,
        }
    }
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
