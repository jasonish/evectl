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
    #[cfg(windows)]
    pub guid: Option<String>,
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

#[cfg(target_os = "windows")]
pub fn get_interfaces() -> Result<Vec<Interface>> {
    use std::process::Command;

    let mut interfaces = vec![];

    // Use PowerShell to get network adapter information
    let ps_script = r#"
        Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
            $adapter = $_
            $config = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            $ipv4 = ($config | Where-Object {$_.AddressFamily -eq 'IPv4'}).IPAddress -join ','
            $ipv6 = ($config | Where-Object {$_.AddressFamily -eq 'IPv6'}).IPAddress -join ','
            
            [PSCustomObject]@{
                Name = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                InterfaceGuid = $adapter.InterfaceGuid
                Status = $adapter.Status
                IPv4 = $ipv4
                IPv6 = $ipv6
            }
        } | ConvertTo-Json -Compress
    "#;

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_script])
        .output()?;

    let stdout = String::from_utf8(output.stdout)?;

    // Parse JSON output
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(adapters) = json.as_array() {
            for adapter in adapters {
                if let Some(obj) = adapter.as_object() {
                    let name = obj.get("Name").and_then(|n| n.as_str()).unwrap_or("");
                    let guid = obj
                        .get("InterfaceGuid")
                        .and_then(|g| g.as_str())
                        .unwrap_or("");

                    if name.is_empty() || guid.is_empty() {
                        continue;
                    }

                    let mut interface = Interface {
                        name: name.to_string(),
                        status: "UP".to_string(),
                        guid: Some(guid.trim_matches('{').trim_matches('}').to_string()),
                        ..Default::default()
                    };

                    // Parse IPv4 addresses
                    if let Some(ipv4) = obj.get("IPv4").and_then(|v| v.as_str()) {
                        for ip in ipv4.split(',') {
                            let ip = ip.trim();
                            if !ip.is_empty() {
                                interface.addr4.push(ip.to_string());
                            }
                        }
                    }

                    // Parse IPv6 addresses
                    if let Some(ipv6) = obj.get("IPv6").and_then(|v| v.as_str()) {
                        for ip in ipv6.split(',') {
                            let ip = ip.trim();
                            if !ip.is_empty() && !ip.starts_with("fe80") {
                                // Skip link-local
                                interface.addr6.push(ip.to_string());
                            }
                        }
                    }

                    interfaces.push(interface);
                }
            }
        } else if let Some(adapter) = json.as_object() {
            // Single adapter case
            let name = adapter.get("Name").and_then(|n| n.as_str()).unwrap_or("");
            let guid = adapter
                .get("InterfaceGuid")
                .and_then(|g| g.as_str())
                .unwrap_or("");

            if !name.is_empty() && !guid.is_empty() {
                let mut interface = Interface {
                    name: name.to_string(),
                    status: "UP".to_string(),
                    guid: Some(guid.trim_matches('{').trim_matches('}').to_string()),
                    ..Default::default()
                };

                // Parse IPv4 addresses
                if let Some(ipv4) = adapter.get("IPv4").and_then(|v| v.as_str()) {
                    for ip in ipv4.split(',') {
                        let ip = ip.trim();
                        if !ip.is_empty() {
                            interface.addr4.push(ip.to_string());
                        }
                    }
                }

                // Parse IPv6 addresses
                if let Some(ipv6) = adapter.get("IPv6").and_then(|v| v.as_str()) {
                    for ip in ipv6.split(',') {
                        let ip = ip.trim();
                        if !ip.is_empty() && !ip.starts_with("fe80") {
                            interface.addr6.push(ip.to_string());
                        }
                    }
                }

                interfaces.push(interface);
            }
        }
    }

    Ok(interfaces)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn get_interfaces() -> Result<Vec<Interface>> {
    Ok(vec![])
}
