# Changelog

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
