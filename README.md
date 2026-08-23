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

## Installation the Easy Way

### Linux

```bash
mkdir ~/evectl
cd ~/evectl
curl -sSf https://evebox.org/evectl.sh | sh
./evectl
```

### Windows PowerShell

```powershell
irm https://evebox.org/evectl.ps1 | iex
evectl.exe
```

The Windows installer verifies the download, installs `evectl.exe` in
`$env:LOCALAPPDATA\evectl\bin`, and offers to add that directory to your
user `PATH`.

You can also download EveCtl directly from
https://evebox.org/files/evectl/.

On first run, follow the setup wizard and select your network
interface, then select "Start" from the main menu.

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
