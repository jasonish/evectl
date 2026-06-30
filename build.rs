// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::env;
use std::process::Command;

fn main() {
    // Make the target triple available to the env! macro. This is used so the binary
    // can figure out its self-update URL.
    println!("cargo:rustc-env=TARGET={}", env::var("TARGET").unwrap());

    // Version string, e.g. 0.2.20260630+c5c26d00b (or +<hash>-dirty):
    //
    //   0.2          generation -- major.minor from Cargo.toml, bumped by hand
    //                only at generation boundaries
    //   20260630     commit date -- synthesized here, NOT stored in Cargo.toml
    //   +c5c26d00b   short commit hash
    //
    // Releases compute this on the host (where git works) and pass it through
    // the cross/Docker builds as EVECTL_VERSION (see Cross.toml and the deploy
    // script). A plain `cargo build`/`cargo run` derives it from git directly.
    // With neither (e.g. a source tarball) it falls back to the bare Cargo.toml
    // version.
    let pkg = env::var("CARGO_PKG_VERSION").unwrap();
    let generation = major_minor(&pkg);
    let version = env::var("EVECTL_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| git_stamp(&generation))
        .unwrap_or(pkg);
    println!("cargo:rustc-env=EVECTL_VERSION={version}");

    // Re-stamp when HEAD moves (commit/checkout) or the override changes.
    println!("cargo:rerun-if-env-changed=EVECTL_VERSION");
    println!("cargo:rerun-if-changed=.git/logs/HEAD");
}

/// `major.minor` of a semver string, e.g. "0.2.0" -> "0.2".
fn major_minor(pkg: &str) -> String {
    let mut parts = pkg.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor)) => format!("{major}.{minor}"),
        _ => pkg.to_string(),
    }
}

/// `<generation>.<commit-date>+<short-hash>[-dirty]`, or `None` outside a git
/// checkout or when git is unavailable.
fn git_stamp(generation: &str) -> Option<String> {
    let date = git(&["show", "-s", "--format=%cd", "--date=format:%Y%m%d", "HEAD"])
        .filter(|s| !s.is_empty())?;
    let hash = git(&["rev-parse", "--short=9", "HEAD"]).filter(|s| !s.is_empty())?;
    let dirty = git(&["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let suffix = if dirty { "-dirty" } else { "" };
    Some(format!("{generation}.{date}+{hash}{suffix}"))
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}
