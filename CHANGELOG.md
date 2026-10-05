# Changelog

## [Unreleased]

### Added

- Linux self-updates now offer to restart all enabled services after updating,
  with a persistent menu reminder if declined. Command-line updates print the
  instance-specific restart command; `evectl update --restart` opts into a
  restart after successful updates. Failed restarts retain the reminder and
  report failure
- Windows EveBox server settings now match Linux: remote access, bind
  address, TLS, authentication, and admin password reset. The setup
  wizard asks the same server questions as Linux. OpenSearch and
  Elasticsearch datastores remain Linux only. Existing Windows
  installations keep running without TLS and authentication until
  changed in Configure > Configure EveBox Server
- Windows full packet capture settings now include agent ID/key editing and
  confirmed removal of old captures after capture is disabled and Suricata stops
- Linux Manage Rules menu actions to refresh rule sources and list enabled
  rulesets, matching Windows
- Windows EveBox release-channel selection (Development or Release) in the
  setup wizard, Configure menu, and `evectl config set-evebox-channel`.
  The setting is shared by the server and agent and applied on install or
  Update. Release resolves the latest stable version from the official
  manifest; Development remains the default, matching Linux's main image
- Opt-in full packet capture on Windows: Suricata writes rotating
  256 MB PCAP files per processing thread under
  `%LOCALAPPDATA%\evectl\suricata\log\pcap`, with configurable total
  retention (100 files by default, rounded down to a multiple of the
  thread count, with at least one file per thread). Enable it from
  "Configure Full Packet Capture" and restart services. Captures are
  available through the local EveBox server or an agent connected to a
  remote server; agent setups prompt for an agent ID and matching key
- Opt-in full packet capture (Linux only): Suricata writes a rotating
  pcap spool that is served through the EveBox web UI, either by the
  local EveBox server or by the EveBox agent on behalf of a remote
  server. Configured from the new "Configure Full Packet Capture"
  menu, with a retention setting as a total file count. Agent
  installations are prompted for an agent ID and the matching agent
  key issued on the server (`evebox config agents add <agent-id>`)
- Opt-in Suricata file extraction on Windows, using the same Suricata
  menu settings and extraction-limit handling as Linux. Extracted files
  are stored under `%LOCALAPPDATA%\evectl\suricata\log\filestore` and
  served by the local EveBox server or agent, independently of full packet
  capture. A native EveCtl housekeeping process provides age-based
  retention (seven days by default; zero keeps files forever), with no
  Python or `suricatactl` dependency. Stop, restart, uninstall and
  foreground shutdown include the worker
- Opt-in Suricata file extraction (Linux only), disabled by default:
  "Enable File Extraction" in the Suricata menu stores files seen in
  HTTP, SMTP, FTP, SMB and NFS traffic under
  `data/suricata/log/filestore`, named by SHA256. Stores files
  matching `filestore` rules, or all files with force-filestore.
  A max extract size (default 4mb) raises the Suricata limits needed
  to extract files up to that size; larger files are stored
  truncated. Extracted files are deleted after 7 days by default.
  The local EveBox server or agent serves extracted files for download
  from events containing their SHA256; agents use the agent ID and key
  independently of full packet capture
- EveBox agent ID and key settings in the EveBox Agent menu on Linux
  and Windows; the ID is stamped on the agent's events and identifies it to
  the server
- `-D`/`--data-directory` option (Linux only) to select the instance
  directory, allowing multiple instances on one host
- OpenSearch as a bundled search-engine option alongside
  Elasticsearch, with OpenSearch now the recommended engine
- Elasticsearch configuration menu with a configurable container
  memory limit (default 2GB)
- `evectl uninstall` command (command line only): stops all services
  and removes the data files, then interactively offers to also
  remove the configuration, the instance directory, and finally the
  EveCtl binary. `--config` removes the configuration without
  prompting, `--all` performs a full uninstall, additionally removing
  container images and the systemd unit on Linux, the
  EveBox/Suricata/Npcap installations and desktop shortcuts on
  Windows, and the EveCtl binary itself, and `--yes` skips all
  prompts, removing only what the flags name. Only files EveCtl
  created are removed; the instance directory itself is left in place
  if it holds anything else

### Changed

- Windows installations now use Suricata 8.0.7
- Windows `evectl update` refreshes enabled EveBox installations from the
  selected channel even when the version number is unchanged. It records
  the installed channel and build revision, and stages and validates the
  new build before replacing installed files while preserving data.
  Channel switches can intentionally downgrade to a stable release;
  back up data first. Disabled components are no longer upgraded
- Windows: `evectl uninstall` now stops services and removes the data
  files by default instead of uninstalling the EveBox, Suricata, and
  Npcap components; the component uninstall is part of
  `evectl uninstall --all` and remains available from the menu
- Linux now defaults to storing configuration and data in
  `~/.config/evectl` instead of the current directory, so it no longer
  matters where EveCtl is run from. An existing `evectl.toml` in the
  current directory is still respected. The systemd unit now records
  the instance directory explicitly instead of relying on the working
  directory
- Enable DHCP extended Eve output and Suricata version fields by default
- Update reqwest to 0.13: TLS certificate verification now uses the system
  trust store merged with the bundled Mozilla roots, so locally installed
  CAs are honored and hosts without ca-certificates still work
- Update sha2 to 0.11 and toml to 1.1
- Update Elasticsearch to 8.19.19

### Fixed

- Re-enabling EveBox server authentication no longer re-enables TLS instead
- Packet-capture removal rechecks Suricata state after confirmation. On Linux,
  removal is blocked while Suricata is restarting or its state cannot be checked
- Suricata interface discovery errors are reported without closing the
  configuration menu; canceling interface selection keeps the previous interface
- Linux extracted-file removal is blocked while Suricata or housekeeping is
  running or restarting, or when container state cannot be determined. Service
  state is rechecked after confirmation on both Linux and Windows
- Rule-management errors are reported without closing the Manage Rules menu;
  Linux rule-update failures now propagate to callers instead of appearing
  successful. Enabled rulesets missing from the source index can still be
  disabled on Linux
- Windows upgrades exit immediately when EveCtl itself is updated, without
  updating components, restarting services, returning to the menu, or prompting
  for Enter. Apply the staged binary after exit using a console-free helper.
  Save a reminder recommending the menu's Restart action until a full stack
  restart succeeds
- Windows file-extraction housekeeping no longer locks the EveCtl executable
  against self-update. Failed staged-update copies retain the download for retry
- Windows background startup no longer stalls after launching file-extraction
  housekeeping. Launch services directly with native Windows process creation,
  returning their PID immediately instead of waiting for a PowerShell launcher's
  captured pipes to close. Housekeeping logs go directly to files
- Extracted-file cleanup now runs in a separate housekeeping container,
  surviving Suricata restarts. Requires a Suricata image with Python 3 and
  `suricatactl filestore prune`. Cleanup includes old files in `tmp/`;
  retention 0 still disables cleanup. Run `evectl restart` after upgrading
  to retire the previous cleanup loop
- Relabel container bind mounts on SELinux hosts so EveBox and Suricata
  can access their host directories, and create required directories for
  server-only and agent-only installations
- Retry failed Linux start-on-boot launches and restart containers that
  exit unexpectedly, without depending on a particular container-runtime
  systemd unit
- Preserve the selected Docker or Podman runtime in the Linux systemd unit
- Windows: restart Suricata after a rule update changes the rules, as
  Suricata on Windows can't reload rules in place
- Apply generated JA4 Suricata overrides when starting Suricata
- Restart services in detached mode instead of foreground debug mode

## [0.3.0] - 2026-06-30

### Added

- Rolling version stamp: `evectl version` now reports
  `<generation>.<commit-date>+<short-hash>` for exact build traceability

### Changed

- Allow binding EveBox server to a specific IP address for multi-homed hosts
- Set EveBox server data/config directories via environment variables
- Update Elasticsearch to 8.19.10
- Pull image on Elasticsearch update
- Run self-update before pulling container images so changed defaults come
  from the newly installed binary
- Return to the EveCtl menu after a menu-initiated update, even when the
  binary was replaced
- Use the EveBox `main` branch instead of `master`

### Fixed

- Check the exit status of external commands so failed operations no longer
  report success
- Fix root systemd command execution
- Fix the exit menu option restarting the main menu instead of exiting it

## [0.2.0] - 2026-01-20

### Added

- Bind interface option for EveBox server
