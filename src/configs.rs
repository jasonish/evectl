// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::path::Path;

// No prelude as this is exported in the library and the prelude isn't
// for now.
use anyhow::Result;
use tracing::info;

pub const AF_PACKET_STUB: &str = "
%YAML 1.1
---

# Do not edit, automatically generated on every restart.

af-packet:
  - interface: default
    threads: auto
    cluster-id: 131
    tpacket-v3: yes
";

pub fn write_af_packet_stub(path: &Path) -> Result<()> {
    info!("Writing af-packet partial to {}", path.display());
    std::fs::write(path, AF_PACKET_STUB)?;
    Ok(())
}
