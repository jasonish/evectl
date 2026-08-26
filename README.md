# EveCtl - Suricata/EveBox

EveCtl is a tool to easily run Suricata and EveBox on Linux and
Windows. Linux systems use Docker or Podman, while Windows systems use
native Suricata, EveBox, and Npcap installations.

## System Requirements

### Linux

- An x86_64 or Aarch64 based Linux distribution with Docker or
  Podman. This includes most Linux distributions available today,
  including Raspberry Pi OS with a 64-bit update applied.
- Root access.

### Windows

- 64-bit Windows on an x86_64 processor.
- PowerShell and permission to approve installer elevation prompts.

## Installation

### Linux

Install EveCtl with the following command:

```bash
curl -sSf https://evebox.org/evectl.sh | sh
```

The installer verifies your platform, downloads `evectl`, and asks
where to install it:

- `~/.local/bin` (recommended): a per-user install that does not
  require `sudo`. This directory is on the `PATH` by default on most
  Linux distributions.
- `/usr/local/bin`: a system-wide install that requires `sudo`.

To skip the prompt, set `EVECTL_INSTALL_DIR`, for example:

```bash
curl -sSf https://evebox.org/evectl.sh | EVECTL_INSTALL_DIR=/usr/local/bin sh
```

Run EveCtl with:

```bash
evectl
```

### Windows PowerShell

Install EveCtl with the PowerShell equivalent of the Linux `curl`
command:

```powershell
irm https://evebox.org/evectl.ps1 | iex
```

The installer verifies the download, installs `evectl.exe` in
`$env:LOCALAPPDATA\evectl\bin`, and offers to add that directory to your
user `PATH`. Run it with:

```powershell
evectl
```

You can also download EveCtl directly from
https://evebox.org/files/evectl/.

On first run, follow the setup wizard and select your network
interface, then select "Start" from the main menu.

## Configuration and Data

On Linux, EveCtl stores its configuration and data in
`~/.config/evectl` by default (note that EveCtl typically runs as
root, so this is usually `/root/.config/evectl`). On Windows the
equivalent is `%LOCALAPPDATA%\evectl`.

For compatibility with older versions, if an `evectl.toml` exists in
the current directory it will be used instead.

On Linux you can run multiple instances, or place the configuration
and data somewhere else, with the `-D`/`--data-directory` option:

```bash
evectl -D /var/lib/evectl-sensor1
```

This option is not available on Windows, where the location is
fixed.

## Building

If you just want to use EveCtl you can download a pre-compiled
binary. The following is only for those who wish to compile EveCtl
themselves.

### For Host OS

```
cargo build --release
```

### Static Linux Targets

Static Linux binaries for x86_64 and other platforms can be built with
the `cross` tool. To install `cross`:

```
cargo install cross
```

#### x86_64

```
cross build --release --target x86_64-unknown-linux-musl
```

#### Aarch64 (Raspberry Pi 64 bit)

```
cross build --release --target aarch64-unknown-linux-musl
```
