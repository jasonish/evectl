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

### Updating on Linux

The menu's **Update** action checks for an EveCtl self-update and pulls
container images. If EveCtl changes, the new binary automatically finishes
updating. Services are not silently restarted: the menu asks whether to
restart all enabled services, briefly interrupting monitoring.

If you decline, **Restart (recommended)** and a warning remain in the menu
until a full restart succeeds. Command-line updates do not prompt for a
restart; they print the command to run for the selected instance. To explicitly
restart all enabled services after a successful update:

```bash
evectl update --restart
# Or select an instance and runtime:
evectl --podman -D /var/lib/evectl-sensor1 update --restart
```

Failed updates do not automatically restart services. A failed restart keeps
the reminder and returns a nonzero exit status.

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

If `evectl upgrade` (or the menu's **Update** action) downloads an EveCtl
self-update, it exits immediately without an Enter prompt or restarting
services. The update is applied after EveCtl exits. Run `evectl` again and
choose **Update** to finish updating the components. The menu will recommend
**Restart** for all enabled services; the reminder stays until a full stack
restart succeeds.

### EveBox release channels on Windows

Windows uses native EveBox binaries rather than container images. Choose
its channel in the setup wizard or under **Configure → EveBox Release
Channel**:

- **Development** (default, matching Linux's `jasonish/evebox:main` image):
  the latest main-branch build.
- **Release**: the latest stable release, resolved from the official release
  manifest instead of a version bundled with EveCtl.

The setting is shared by the EveBox server and agent. From PowerShell:

```powershell
evectl config set-evebox-channel release
evectl update

# To return to development builds:
evectl config set-evebox-channel development
evectl update
```

Omit the channel to choose interactively; `devel` is also accepted for
`development`. The setting is saved in `evectl.toml`:

```toml
[windows]
evebox-channel = "release"
```

For a new installation, `evectl install` uses the selected channel. For an
existing installation, use `evectl update` or the main menu's **Update**
action to apply a channel change; a restart alone does not change the
installed binary. Every Update downloads the latest build from the selected
channel, even if its version number is unchanged. Only enabled components
are updated. Previously running managed services are stopped and restarted,
and EveBox data is preserved. The archive and binary are validated before
replacing the installed files. `evectl info` shows the selected channel,
installed channel, version, and development revision.

Switching from Development to Release may downgrade EveBox. **Back up your
data first**: preserving the files does not guarantee an older release can
read data created by a newer development build. Linux continues to use the
configured Docker/Podman image name; this Windows setting has no effect there.

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

## Full packet capture (Windows)

Enable capture from "Configure" → "Configure Full Packet Capture".
Requires Suricata and either the local EveBox server or the EveBox agent.
Restart services after changing capture or retention settings.
Captures can be retrieved through the EveBox web UI, locally or through
an agent connected to a remote server. Agent setups prompt for an agent ID
and the matching key issued on the server with
`evebox config agents add <agent-id>` (or through its Agents page).
These settings can also be changed in the EveBox Agent menu.

Captures are stored in `%LOCALAPPDATA%\evectl\suricata\log\pcap`.
Suricata uses multi mode, writing separate `log.<thread>.<timestamp>.pcap`
files for each processing thread and rotating each file at 256 MB.
The retention setting is a total file count (100 by default, about 25 GB),
divided across the threads. The effective total is rounded down to a
multiple of the thread count, with at least one file per thread; the
configuration menu shows the effective retention and disk usage.
Disabling capture leaves existing files in place but stops configuring
EveBox retrieval after services restart. Files left over from normal mode
are also left in place and do not count toward the new per-thread retention
limit.

## File extraction (Linux and Windows)

Enable extraction from "Configure" → "Configure Suricata" → "Enable File
Extraction", then restart services. Extraction is disabled by default and
requires Suricata. By default, only files selected by rules using the
`filestore` keyword are stored; enable `outputs.file-store.force-filestore`
to store all files seen in supported protocols (HTTP, SMTP, FTP, SMB and NFS).
The menu also offers a max extract size (default `4mb`) and retention
(default seven days; `0` keeps files forever). Files larger than the configured
size can be stored truncated. Suricata's relevant limits are raised, never lowered.

Files are stored by SHA256 in `data/suricata/log/filestore` on Linux and
`%LOCALAPPDATA%\evectl\suricata\log\filestore` on Windows. The local EveBox
server or agent makes them available through events containing their SHA256.
Agent retrieval uses the agent ID and matching server-issued key, independently
of full packet capture; enabling extraction prompts for these when needed.
Disabling extraction leaves existing files in place and stops cleanup and
EveBox retrieval after restarting services. The Suricata menu offers to remove
leftover extracted files once services are stopped.

**Windows Suricata caveat:** the bundled Suricata 8.0.6 build was observed
converting LF bytes to CRLF in extracted files. Filestore names and EVE SHA256
values still identify the original network content, so the downloaded file's
hash may differ. EveCtl does not rewrite extracted content to work around this
upstream behavior.

### Extracted-file retention (Windows)

EveCtl launches a native `housekeeper` process alongside the Windows stack;
no Python or `suricatactl` installation is needed. It uses a separate executable
copy under `suricata\run`, refreshed whenever the worker starts, so housekeeping
does not prevent updating `evectl.exe`. Cleanup runs immediately
and then every five minutes, deleting files older than the configured retention
by modification time, including files in `tmp/`. Symbolic links and junctions
are not followed. Failed deletions (for example, files still in use) are logged
and retried on the next pass.

The worker runs independently of Suricata's rules-update restarts. Starting or
restarting the stack applies the configured retention; `evectl stop`, uninstall
and foreground shutdown stop the worker. A retention of `0`, disabled extraction
or disabled Suricata prevents cleanup. Background cleanup logs are under
`%LOCALAPPDATA%\evectl\suricata\log\housekeeper-stdout.log` and
`housekeeper-stderr.log`; foreground runs display them in the console.

### Extracted-file retention (Linux)

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
make test-housekeeper
```

`make test-housekeeper` builds the CLI and disables Python bytecode cache
creation for the tests and their subprocesses with `PYTHONDONTWRITEBYTECODE=1`.

Default Python tests include temporary fake-runtime CLI tests for uninstall,
foreground signal shutdown, and same-tag image-ID reconciliation. They never
invoke Docker/Podman or mutate real images; actual runtime image replacement
remains outside this simulated coverage.

Container integration tests are opt-in; see
`src/housekeeper/test_runtime.py` for Docker/Podman commands. They use
isolated instances and disposable files, never live captures or host reboots.

On Windows, the optional EveBox channel smoke test downloads and runs the
official builds' `version` commands in a temporary directory. It tests both
channels, switching in both directions, and replacing the same build without
touching your installation:

```powershell
cargo test installs_and_switches_evebox_release_channels -- --ignored --nocapture
```

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
