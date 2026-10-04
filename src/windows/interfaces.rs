// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Network interface enumeration and selection.

use super::paths::{Paths, ensure_dir, load_evectl_config};
use crate::prelude::*;
use colored::Colorize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(super) struct WindowsInterface {
    pub(super) name: String,
    pub(super) ip_address: String,
    pub(super) guid: String,
}

pub(super) fn windows_interfaces() -> Result<Vec<WindowsInterface>> {
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceLuidToGuid, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses,
        IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };
    use windows::core::GUID;

    fn win32_error_message(code: WIN32_ERROR) -> String {
        io::Error::from_raw_os_error(code.0 as i32).to_string()
    }

    fn adapter_guid(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Result<String> {
        if !adapter.AdapterName.is_null()
            && let Ok(name) = unsafe { adapter.AdapterName.to_string() }
            && let Some(guid) = normalize_interface_guid(&name)
        {
            return Ok(guid);
        }

        let mut guid = GUID::zeroed();
        let status = unsafe { ConvertInterfaceLuidToGuid(&adapter.Luid, &mut guid) };
        if status == NO_ERROR {
            Ok(format!("{guid:?}"))
        } else {
            bail!(
                "Failed to resolve interface GUID: {}",
                win32_error_message(status)
            )
        }
    }

    fn socket_address_to_string(
        address: &windows::Win32::Networking::WinSock::SOCKET_ADDRESS,
    ) -> Option<(String, bool)> {
        if address.lpSockaddr.is_null() {
            return None;
        }

        let family = unsafe { (*address.lpSockaddr).sa_family };
        if family == AF_INET {
            let sockaddr = unsafe { &*(address.lpSockaddr as *const SOCKADDR_IN) };
            let ip: Ipv4Addr = sockaddr.sin_addr.into();
            Some((ip.to_string(), true))
        } else if family == AF_INET6 {
            let sockaddr = unsafe { &*(address.lpSockaddr as *const SOCKADDR_IN6) };
            let ip: Ipv6Addr = sockaddr.sin6_addr.into();
            Some((ip.to_string(), false))
        } else {
            None
        }
    }

    let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
        GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0 | GAA_FLAG_SKIP_DNS_SERVER.0,
    );
    let mut buffer_size = 16 * 1024;
    let mut result = BTreeMap::new();

    for _ in 0..3 {
        let mut buffer = vec![0u8; buffer_size as usize];
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buffer_size,
            )
        };

        if status == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }

        if status != NO_ERROR.0 {
            bail!(
                "GetAdaptersAddresses failed: {}",
                win32_error_message(WIN32_ERROR(status))
            );
        }

        let mut current = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        while !current.is_null() {
            let adapter = unsafe { &*current };
            current = adapter.Next;

            if adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }

            let name = if adapter.FriendlyName.is_null() {
                String::new()
            } else {
                unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default()
            };
            let name = if name.is_empty() {
                if adapter.AdapterName.is_null() {
                    "<unnamed>".to_string()
                } else {
                    unsafe { adapter.AdapterName.to_string() }
                        .unwrap_or_else(|_| "<unnamed>".to_string())
                }
            } else {
                name
            };

            let guid = match adapter_guid(adapter) {
                Ok(guid) => guid,
                Err(err) => {
                    warn!("Skipping network interface '{}': {}", name, err);
                    continue;
                }
            };

            let mut ip_address = String::new();
            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                let address = unsafe { &*unicast };
                if let Some((candidate, is_ipv4)) = socket_address_to_string(&address.Address) {
                    if is_ipv4 {
                        ip_address = candidate;
                        break;
                    }
                    if ip_address.is_empty() {
                        ip_address = candidate;
                    }
                }
                unicast = address.Next;
            }

            result
                .entry(guid.clone())
                .or_insert_with(|| WindowsInterface {
                    name,
                    ip_address,
                    guid,
                });
        }

        let mut interfaces: Vec<_> = result.into_values().collect();
        interfaces.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then(a.guid.cmp(&b.guid))
        });
        return Ok(interfaces);
    }

    bail!("GetAdaptersAddresses failed after repeated buffer resizing")
}

fn normalize_interface_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn is_windows_interface_guid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }

    for (index, byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if *byte != b'-' {
                    return false;
                }
            }
            _ => {
                if !(*byte as char).is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }

    true
}

pub(super) fn normalize_interface_guid(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let value = value
        .strip_prefix(r"\Device\NPF_")
        .or_else(|| value.strip_prefix(r"\device\npf_"))
        .unwrap_or(value)
        .trim_matches(['{', '}']);

    if is_windows_interface_guid(value) {
        Some(value.to_ascii_uppercase())
    } else {
        None
    }
}

pub(super) fn configured_interface_value(paths: &Paths) -> Result<Option<String>> {
    let config = load_evectl_config(paths)?;
    Ok(config
        .suricata
        .interfaces
        .first()
        .and_then(|value| normalize_interface_name(value)))
}

fn find_windows_interface_by_name(name: &str) -> Result<Option<WindowsInterface>> {
    let name = match normalize_interface_name(name) {
        Some(name) => name,
        None => return Ok(None),
    };

    Ok(windows_interfaces()?
        .into_iter()
        .find(|interface| interface.name.eq_ignore_ascii_case(&name)))
}

pub(super) fn configured_interface_guid(paths: &Paths) -> Result<Option<String>> {
    let value = match configured_interface_value(paths)? {
        Some(value) => value,
        None => return Ok(None),
    };

    if let Some(guid) = normalize_interface_guid(&value) {
        return Ok(Some(guid));
    }

    Ok(find_windows_interface_by_name(&value)?.map(|interface| interface.guid))
}

fn set_configured_interface_name(paths: &Paths, name: &str) -> Result<PathBuf> {
    let config_path = paths.config_file();
    ensure_dir(paths.root())?;

    let mut config = load_evectl_config(paths)?;
    config.suricata.interfaces = vec![name.to_string()];
    config.save()?;

    Ok(config_path)
}

fn prompt_for_interface(prompt: &str) -> Result<WindowsInterface> {
    let interfaces = windows_interfaces()?;
    if interfaces.is_empty() {
        bail!("No network interfaces found");
    }

    let mut selections = crate::prompt::Selections::with_index();
    for interface in &interfaces {
        let address = if interface.ip_address.is_empty() {
            "".to_string()
        } else {
            format!("-- {}", interface.ip_address.green().italic())
        };
        selections.push(interface.clone(), format!("{} {}", interface.name, address));
    }

    let selection = inquire::Select::new(prompt, selections.to_vec()).prompt()?;
    Ok(selection.tag)
}

fn prompt_for_interface_and_maybe_save(paths: &Paths) -> Result<WindowsInterface> {
    let interface =
        prompt_for_interface("Suricata: What network interface should Suricata listen on?")?;

    if inquire::Confirm::new("Remember this interface for future runs?")
        .with_default(true)
        .prompt()?
    {
        let config_path = set_configured_interface_name(paths, &interface.name)?;
        println!("Saved default interface: {}", interface.name);
        println!("Resolved interface GUID: {}", interface.guid);
        println!("Config file: {}", config_path.display());
    }

    Ok(interface)
}

pub(super) fn resolve_interface_guid(
    paths: &Paths,
    guid: Option<String>,
    allow_prompt: bool,
) -> Result<String> {
    if let Some(value) = guid.as_deref().and_then(normalize_interface_name) {
        if let Some(guid) = normalize_interface_guid(&value) {
            return Ok(guid);
        }

        if let Some(interface) = find_windows_interface_by_name(&value)? {
            return Ok(interface.guid);
        }

        bail!("Network interface '{}' was not found", value);
    }

    if let Some(guid) = configured_interface_guid(paths)? {
        return Ok(guid);
    }

    if allow_prompt {
        Ok(prompt_for_interface_and_maybe_save(paths)?.guid)
    } else {
        bail!(
            "No interface is configured. Use 'evectl config set-interface', pass --guid <GUID>, or run interactively to choose one."
        )
    }
}

pub(super) fn config_set_interface(paths: &Paths) -> Result<()> {
    let interface = prompt_for_interface("Select Interface")?;
    let config_path = set_configured_interface_name(paths, &interface.name)?;

    println!("Saved default interface: {}", interface.name);
    println!("Resolved interface GUID: {}", interface.guid);
    println!("Config file: {}", config_path.display());

    Ok(())
}

pub(super) fn list_interfaces() -> Result<()> {
    println!("{:<32} {:<39} GUID", "Name", "IP Address");
    for interface in windows_interfaces()? {
        let ip_address = if interface.ip_address.is_empty() {
            "<no IP>"
        } else {
            &interface.ip_address
        };
        println!(
            "{:<32} {:<39} {}",
            interface.name, ip_address, interface.guid
        );
    }

    Ok(())
}
