// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The platform operations behind the shared menus. Each menu is
//! written against its own small trait; a platform implements them
//! all on one type.

pub(crate) trait Platform:
    crate::suricata::configuration::Backend
    + crate::fpc::Backend
    + crate::evebox::configuration::Backend
    + crate::rules::Backend
{
}

impl<T> Platform for T where
    T: crate::suricata::configuration::Backend
        + crate::fpc::Backend
        + crate::evebox::configuration::Backend
        + crate::rules::Backend
{
}
