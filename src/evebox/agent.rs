// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

pub(crate) fn container_name(context: &Context) -> String {
    let parent = context.root.file_name().unwrap().to_string_lossy();
    format!("{}-evectl-evebox-agent", parent)
}
