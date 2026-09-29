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

## Extracted-file retention (Linux)

When Suricata file extraction is enabled, EveCtl runs a separate
`<instance-prefix>-housekeeper` container using the configured Suricata
image. That image must include Python 3.7+ (`python3` on PATH) and
`suricatactl filestore prune`; EveCtl checks compatibility and mounted
filestore access before starting cleanup. The executable worker runs directly
as `evectl-housekeeper` (using a Python shebang), which is also the command
shown by `docker ps`. On first start, if Suricata has not created its filestore
yet, the check validates the mounted log directory instead. The worker waits
for Suricata to create the filestore and retries on its normal schedule; it
does not change directory ownership or permissions.

Cleanup runs immediately and then every five minutes, pruning the whole
filestore, **including `tmp/`**, by modification time. The default retention
is seven days; `suricata.file-extraction.max-age-days = 0` disables cleanup.
Each command has a four-minute timeout. Failures are logged and retried;
shutdown terminates the active command, escalating after five seconds.
A zero command exit status does not guarantee every file was deleted:
`suricatactl` can log individual deletion failures without failing the command.
Use `evectl logs` to inspect cleanup activity.

Housekeeping survives Suricata restarts independently. `evectl start`
restores a missing/stopped worker, replaces it when settings or its image
change, and removes it when cleanup is disabled. Older `-housekeeping`
containers are removed automatically on start or stop. Image updates take effect
on the next start/restart. `evectl stop`, restart, uninstall and foreground
session shutdown include housekeeping. After upgrading from the old
exec-based cleaner, run `evectl restart` once to retire the old cleanup loop.

Housekeeping alone uses `unless-stopped`. For boot startup, install EveCtl's
existing systemd integration (`evectl systemd install`), especially with
Podman; restart policy alone is not a portable reboot guarantee. A manual
runtime stop suppresses runtime restart, but a later explicit or systemd
`evectl start` reconciles all configured services and starts cleanup again.

The EVE JSON spool backstop remains exec-based and is **not** made durable
by this change. Scheduled rule updates are not implemented.

## Building

If you just want to use EveCtl you can download a pre-compiled
binary. The following is only for those who wish to compile EveCtl
themselves.

### Tests

```bash
cargo test
cargo build # Builds the CLI used by isolated fake-runtime tests.
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s src/housekeeper -p 'test_*.py' -v
```

Default Python tests include temporary fake-runtime CLI tests for uninstall,
foreground signal shutdown, and same-tag image-ID reconciliation. They never
invoke Docker/Podman or mutate real images; actual runtime image replacement
remains outside this simulated coverage.

Container integration tests are opt-in; see
`src/housekeeper/test_runtime.py` for Docker/Podman commands. They use
isolated instances and disposable files, never live captures or host reboots.

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
