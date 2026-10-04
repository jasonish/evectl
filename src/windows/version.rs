// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Loose dotted version comparison for installed components.

pub(super) fn compare_versions(current: &str, target: &str) -> Option<std::cmp::Ordering> {
    let current_parts = parse_version_parts(current)?;
    let target_parts = parse_version_parts(target)?;
    let max_len = current_parts.len().max(target_parts.len());

    for idx in 0..max_len {
        let lhs = *current_parts.get(idx).unwrap_or(&0);
        let rhs = *target_parts.get(idx).unwrap_or(&0);
        let ord = lhs.cmp(&rhs);
        if ord != std::cmp::Ordering::Equal {
            return Some(ord);
        }
    }

    Some(std::cmp::Ordering::Equal)
}

pub(super) fn parse_version_parts(version: &str) -> Option<Vec<u32>> {
    let mut parts = vec![];
    let mut current = String::new();

    for ch in version.trim().chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            let value = match current.parse::<u32>() {
                Ok(value) => value,
                Err(_) => return None,
            };
            parts.push(value);
            current.clear();
        }
    }

    if !current.is_empty() {
        let value = match current.parse::<u32>() {
            Ok(value) => value,
            Err(_) => return None,
        };
        parts.push(value);
    }

    if parts.is_empty() { None } else { Some(parts) }
}
