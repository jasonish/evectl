// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

pub(crate) fn getuid() -> u32 {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::getuid() as u32
    }
    #[cfg(not(target_os = "linux"))]
    0
}

/// Number of online CPUs, as Suricata counts them for `threads:
/// auto` (sysconf's _SC_NPROCESSORS_ONLN). Unlike
/// `available_parallelism`, this ignores any CPU affinity or cgroup
/// quota applied to this process, which Suricata in its own container
/// does not share.
pub(crate) fn online_cpus() -> usize {
    #[cfg(unix)]
    {
        let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if n > 0 {
            return n as usize;
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// The system hostname, which is what the EveBox agent identifies
/// itself as when no agent ID is configured.
#[cfg(unix)]
pub(crate) fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..len]).trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

#[cfg(windows)]
pub(crate) fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn hostname() -> Option<String> {
    None
}

#[derive(Debug, Default)]
pub(crate) struct Interface {
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
pub(crate) fn get_interface_ip(interface: &str) -> Result<String> {
    let interfaces = get_interfaces()?;
    let iface = interfaces
        .iter()
        .find(|iface| iface.name == interface)
        .ok_or_else(|| anyhow!("Interface {} not found", interface))?;
    iface
        .addr4
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("Interface {} has no IPv4 address", interface))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn get_interface_ip(_interface: &str) -> Result<String> {
    bail!("get_interface_ip is only supported on Linux")
}

/// Resolve a bind value to an IP address.
///
/// If `value` is an IP address, it is returned as-is.
/// Otherwise, it is treated as an interface name and resolved to the first
/// IPv4 address on that interface.
pub(crate) fn resolve_interface_or_ip(value: &str) -> Result<String> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok(value.to_string());
    }
    get_interface_ip(value)
}

/// The IPv4 address the system is most likely reachable at: the
/// first address of the first interface that is up, falling back to
/// the loopback address.
pub(crate) fn primary_ipv4() -> Option<String> {
    let interfaces = match get_interfaces() {
        Ok(interfaces) => interfaces,
        Err(err) => {
            error!("Failed to get system interfaces: {err}");
            return None;
        }
    };
    let mut addr: Option<&String> = None;
    for interface in &interfaces {
        // Only consider IPv4 addresses for now.
        if interface.addr4.is_empty() {
            continue;
        }
        // Loopback is only a placeholder until an interface that is up
        // provides a better address.
        let replace = (interface.name == "lo" && addr.is_none())
            || (interface.status == "UP"
                && addr.is_none_or(|previous| previous.starts_with("127")));
        if replace {
            addr = interface.addr4.first();
        }
    }
    addr.cloned()
}

/// Get the network interfaces and their addresses.
///
/// We parse the output of the "ip" command as we may need to do this
/// by executing a command in a Docker container.
///
/// Note: Newer versions of "ip" support JSON output.
#[cfg(target_os = "linux")]
pub(crate) fn get_interfaces() -> Result<Vec<Interface>> {
    use std::process::Command;

    let output = Command::new("ip")
        .args(["--brief", "address", "show"])
        .output()?;
    if !output.status.success() {
        bail!(
            "'ip address show' failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout)?;
    let mut interfaces = vec![];
    for line in stdout.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let [name, status, addrs @ ..] = parts.as_slice() else {
            debug!("Ignoring unexpected 'ip' output: {line}");
            continue;
        };

        // Get the name minus the @suffix which isn't supported by
        // Suricata.
        let name = name.split('@').next().unwrap_or(name);
        let mut interface = Interface {
            name: name.to_string(),
            status: status.to_string(),
            ..Default::default()
        };
        for addr in addrs {
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
pub(crate) fn get_interfaces() -> Result<Vec<Interface>> {
    Ok(vec![])
}
