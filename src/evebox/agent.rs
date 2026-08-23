// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

pub(crate) fn container_name(context: &Context) -> String {
    format!("{}-evebox-agent", context.container_prefix())
}
