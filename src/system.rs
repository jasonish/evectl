// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use anyhow::Result;

pub fn getuid() -> u32 {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::getuid() as u32
    }
    #[cfg(not(target_os = "linux"))]
    0
}

#[derive(Debug, Default)]
pub struct Interface {
    pub name: String,
    pub status: String,
    pub addr4: Vec<String>,
    pub addr6: Vec<String>,
}

/// Get the IPv4 address of a specific network interface.
///
/// Returns the first IPv4 address assigned to the interface, or an error
/// if the interface doesn't exist or has no IPv4 address.
#[cfg(target_os = "linux")]
pub fn get_interface_ip(interface: &str) -> Result<String> {
    let interfaces = get_interfaces()?;
    for iface in interfaces {
        if iface.name == interface {
            if let Some(addr) = iface.addr4.first() {
                return Ok(addr.clone());
            }
            anyhow::bail!("Interface {} has no IPv4 address", interface);
        }
    }
    anyhow::bail!("Interface {} not found", interface)
}

#[cfg(not(target_os = "linux"))]
pub fn get_interface_ip(_interface: &str) -> Result<String> {
    anyhow::bail!("get_interface_ip is only supported on Linux")
}

/// Resolve a bind value to an IP address.
///
/// If `value` is an IP address, it is returned as-is.
/// Otherwise, it is treated as an interface name and resolved to the first
/// IPv4 address on that interface.
pub fn resolve_interface_or_ip(value: &str) -> Result<String> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok(value.to_string());
    }
    get_interface_ip(value)
}

/// Get the network interfaces and their addresses.
///
/// We parse the output of the "ip" command as we may need to do this
/// by executing a command in a Docker container.
///
/// Note: Newer versions of "ip" support JSON output.
#[cfg(target_os = "linux")]
pub fn get_interfaces() -> Result<Vec<Interface>> {
    use std::process::Command;

    let output = Command::new("ip")
        .args(["--brief", "address", "show"])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let mut interfaces = vec![];
    for line in stdout.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(' ').filter(|part| !part.is_empty()).collect();

        // Get the name minus the @suffix which isn't supported by
        // Suricata.
        let name = parts[0].split('@').next().unwrap();
        let status = &parts[1];
        let mut interface = Interface {
            name: name.to_string(),
            status: status.to_string(),
            ..Default::default()
        };
        for addr in &parts[2..] {
            let addr = addr.split('/').next().unwrap_or(addr);
            if addr.contains('.') {
                interface.addr4.push(addr.to_string());
            } else {
                interface.addr6.push(addr.to_string());
            }
        }
        interfaces.push(interface);
    }
    Ok(interfaces)
}

#[cfg(not(target_os = "linux"))]
pub fn get_interfaces() -> Result<Vec<Interface>> {
    Ok(vec![])
}
