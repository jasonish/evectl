// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

pub(crate) const AF_PACKET_STUB: &str = "
%YAML 1.1
---

# Do not edit, automatically generated on every restart.

default-packet-size: 65549

af-packet:
  - interface: default
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    block-size: 2097152
";

pub(crate) fn write_af_packet_stub(context: &Context) -> Result<()> {
    let path = context.config_directory.join("af-packet.yaml");
    info!("Writing af-packet partial to {}", path.display());
    std::fs::write(&path, AF_PACKET_STUB)?;
    Ok(())
}
