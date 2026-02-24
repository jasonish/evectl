// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::{ArgBuilder, container::Container, prelude::*};

pub(crate) fn container_name(context: &Context) -> String {
    let prefix = context.root.file_name().unwrap().to_string_lossy();
    format!("{}-evectl-evebox-server", prefix)
}

pub(crate) fn reset_password(context: &mut Context) {
    let image = context.image_name(Container::EveBox);
    let mut args = ArgBuilder::new();
    args.add("run");

    let host_config_directory = context.config_dir().join("evebox").join("server");
    std::fs::create_dir_all(&host_config_directory).unwrap();
    args.add(format!(
        "--volume={}:/config",
        host_config_directory.display()
    ));

    args.extend(&[
        "--rm", "-it", &image, "evebox", "-D", "/config", "config", "users", "rm", "admin",
    ]);
    info!("Executing {:?}", args.args);
    let _ = context.manager.command().args(&args.args).status();

    let mut args = ArgBuilder::new();
    args.add("run");
    args.add(format!(
        "--volume={}:/config",
        host_config_directory.display()
    ));
    args.extend(&[
        "--rm",
        "-it",
        &image,
        "evebox",
        "-D",
        "/config",
        "config",
        "users",
        "add",
        "--username",
        "admin",
    ]);
    let _ = context.manager.command().args(&args.args).status();
}
