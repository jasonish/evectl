// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use serde::Deserialize;
use std::path::Path;
use std::process::Command;

pub const DEFAULT_SURICATA_IMAGE: &str = "docker.io/jasonish/suricata:latest";
pub const DEFAULT_EVEBOX_IMAGE: &str = "docker.io/jasonish/evebox:main";
// Recover a container whose process exits with an error. Note that the
// container runtime may also restore these containers itself when it
// starts at boot (before `evectl start` runs), so starting must remain
// idempotent and tolerate containers that are already running.
pub(crate) const RESTART_POLICY_ARG: &str = "--restart=on-failure";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ContainerManager {
    Docker(DockerManager),
    Podman(PodmanManager),
}

impl std::fmt::Display for ContainerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            ContainerManager::Docker(_) => "Docker",
            ContainerManager::Podman(_) => "Podman",
        };
        write!(f, "{name}")
    }
}

impl ContainerManager {
    pub(crate) fn command(&self) -> Command {
        Command::new(self.bin())
    }

    pub(crate) fn bin(&self) -> &str {
        match self {
            Self::Docker(docker) => docker.bin(),
            Self::Podman(podman) => podman.bin(),
        }
    }

    /// Test if a container manager exists.
    pub(crate) fn exists(&self) -> bool {
        Command::new(self.bin())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
    }

    /// Return true if the container manager is Podman.
    pub(crate) fn is_podman(&self) -> bool {
        matches!(self, ContainerManager::Podman(_))
    }

    /// Return true if the container manager is Docker.
    pub(crate) fn is_docker(&self) -> bool {
        matches!(self, ContainerManager::Docker(_))
    }

    /// Format a bind mount, adding a shared SELinux label when SELinux is
    /// enabled on the host.
    pub(crate) fn bind_mount(&self, source: &Path, target: &str) -> String {
        self.bind_mount_with_options(source, target, &[])
    }

    /// Format a bind mount with container-runtime volume options.
    pub(crate) fn bind_mount_with_options(
        &self,
        source: &Path,
        target: &str,
        options: &[&str],
    ) -> String {
        format_bind_mount(source, target, options, selinux_enabled())
    }

    pub(crate) fn version(&self) -> Result<String> {
        let output = self
            .command()
            .args(["version", "--format", "{{json . }}"])
            .output()?;
        if !output.status.success() {
            bail!(String::from_utf8_lossy(&output.stderr).to_string());
        } else if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
            if let Some(version) = json["Client"]["Version"].as_str() {
                return Ok(version.to_string());
            }
            if let Some(version) = json["Version"].as_str() {
                return Ok(version.to_string());
            }
        }
        bail!(
            "Failed to find {} version in output: {}",
            self,
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// Quietly remove container.
    pub(crate) fn quiet_rm(&self, name: &str) {
        let _ = self.command().args(["rm", "--force", name]).output();
    }

    pub(crate) fn stop(&self, name: &str, signal: Option<&str>) -> Result<()> {
        let mut cmd = self.command();
        cmd.arg("stop");

        // Custom stop signals are not supported on Podman.
        if self.is_docker() {
            cmd.args(["--signal", signal.unwrap_or("SIGTERM")]);
        }
        cmd.arg(name);
        let output = cmd.output()?;
        if !output.status.success() {
            bail!(String::from_utf8_lossy(&output.stderr).to_string());
        }
        Ok(())
    }

    /// Remove an image.
    pub(crate) fn remove_image(&self, name: &str) -> Result<()> {
        let output = self.command().args(["rmi", name]).output()?;
        if !output.status.success() {
            bail!(String::from_utf8_lossy(&output.stderr).to_string());
        }
        Ok(())
    }

    pub(crate) fn pull(&self, image: &str) -> Result<()> {
        let status = self.command().args(["pull", image]).status()?;
        if status.success() {
            Ok(())
        } else {
            bail!("Pull did not exit successfully")
        }
    }

    pub(crate) fn inspect_first(&self, name: &str) -> Result<InspectEntry> {
        let mut command = self.command();
        command.args(["inspect", name]);
        let mut entries: Vec<InspectEntry> = command_json(&mut command)?;
        if entries.is_empty() {
            bail!("{} returned unexpected empty inspect array", self);
        } else {
            Ok(entries.swap_remove(0))
        }
    }

    pub(crate) fn has_image(&self, name: &str) -> bool {
        self.inspect_first(name).is_ok()
    }

    /// Test if a container is running and not in the middle of being
    /// restarted by the container runtime's restart policy.
    pub(crate) fn is_running(&self, name: &str) -> bool {
        if let Ok(state) = self.state(name) {
            return state.running && !state.restarting;
        }
        false
    }

    /// Test if a container is running or being restarted, that is,
    /// something a `stop` should be issued for.
    pub(crate) fn is_active(&self, name: &str) -> bool {
        if let Ok(state) = self.state(name) {
            return state.running || state.restarting;
        }
        false
    }

    /// Return the Inspect.State object for a container.
    ///
    /// If the container doesn't exist an error is returned.
    pub(crate) fn state(&self, name: &str) -> Result<InspectState> {
        match self.inspect_first(name)?.state {
            Some(state) => Ok(state),
            None => bail!("not a container"),
        }
    }

    /// Test if a container exists.
    ///
    /// Any failure results in false.
    pub(crate) fn container_exists(&self, name: &str) -> bool {
        if let Ok(output) = self.command().args(["inspect", name]).output() {
            return output.status.success();
        }
        false
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct PodmanManager {}

impl PodmanManager {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn bin(&self) -> &str {
        "podman"
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct DockerManager {}

impl DockerManager {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn bin(&self) -> &str {
        "docker"
    }
}

/// Command extensions useful for containers.
pub(crate) trait CommandExt {
    /// Like `Command::output`, but return an error on command failure
    /// as well as non-successful exit code.
    fn status_output(&mut self) -> anyhow::Result<Vec<u8>>;

    /// Like `Command::status` but will also fail if the command did
    /// not exit successfully.
    fn status_ok(&mut self) -> Result<()>;
}

impl CommandExt for std::process::Command {
    fn status_output(&mut self) -> Result<Vec<u8>> {
        let output = self.output()?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            bail!(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    fn status_ok(&mut self) -> Result<()> {
        let status = self.status()?;
        if status.success() {
            Ok(())
        } else {
            bail!("Failed with exit code {:?}", status.code())
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct InspectEntry {
    #[serde(rename = "Id")]
    _id: String,

    // Only found when inspecting containers.
    #[serde(rename = "State")]
    state: Option<InspectState>,

    // Only found when inspecting images.
    #[serde(rename = "RepoTags")]
    _repo_tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InspectState {
    #[serde(rename = "Status")]
    pub status: String,

    #[serde(rename = "Running")]
    pub running: bool,

    #[serde(rename = "Restarting", default)]
    pub restarting: bool,

    #[serde(rename = "Error")]
    pub error: String,

    #[serde(rename = "ExitCode")]
    pub exit_code: i32,
}

fn selinux_enabled() -> bool {
    // This interface exists whenever SELinux is enabled, in both enforcing
    // and permissive modes. Relabel in either mode so the mounts keep working
    // if the host is later switched to enforcing mode.
    Path::new("/sys/fs/selinux/enforce").exists()
}

fn format_bind_mount(
    source: &Path,
    target: &str,
    options: &[&str],
    selinux_enabled: bool,
) -> String {
    let mut options = options.to_vec();
    if selinux_enabled && !options.iter().any(|option| matches!(*option, "z" | "Z")) {
        // EveCtl mounts are shared by long-running and short-lived containers,
        // so use the shared SELinux label rather than the private `:Z` label.
        options.push("z");
    }

    let options = if options.is_empty() {
        String::new()
    } else {
        format!(":{}", options.join(","))
    };
    format!("{}:{target}{options}", source.display())
}

fn command_json<T>(command: &mut Command) -> Result<T>
where
    T: serde::de::DeserializeOwned + std::fmt::Debug,
{
    let output = command.output()?;
    if !output.status.success() {
        if output.stderr.is_empty() {
            bail!("Command failed with no stderr output");
        } else {
            bail!(String::from_utf8_lossy(&output.stderr).to_string());
        }
    } else {
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}

pub(crate) fn find_manager(podman: bool) -> Option<ContainerManager> {
    if !podman {
        debug!("Looking for Docker container engine");

        let manager = ContainerManager::Docker(DockerManager::new());
        if manager.exists() {
            info!("Found Docker container engine");
            if let Ok(version) = manager.version() {
                debug!("Found Docker version {version}");
                return Some(manager);
            }
        } else {
            info!("Docker not found");
        }
    };

    debug!("Looking for Podman container engine");
    let manager = ContainerManager::Podman(PodmanManager::new());
    if manager.exists() {
        info!("Found Podman container engine");
        if let Ok(version) = manager.version() {
            debug!("Found Podman version {version}");
            match semver::Version::parse(&version) {
                Ok(version) => {
                    if version.major < 4 || (version.major == 4 && version.minor < 6) {
                        error!("Podman version must be at least 4.7.0");
                    } else {
                        return Some(manager);
                    }
                }
                Err(_) => {
                    error!("Failed to parse Podman version");
                }
            }
        }
    } else {
        info!("Podman not found");
    }

    None
}

#[derive(Debug)]
pub(crate) enum Container {
    Suricata,
    EveBox,
}

pub(crate) struct SuricataContainer {
    context: Context,
}

impl SuricataContainer {
    pub(crate) fn new(context: Context) -> Self {
        Self { context }
    }

    pub(crate) fn volumes(&self) -> Vec<String> {
        let libdir = self.context.config_dir().join("suricata").join("lib");
        let logdir = self.context.data_dir().join("suricata").join("log");
        let rundir = self.context.data_dir().join("suricata").join("run");

        let volumes = vec![
            self.context
                .manager
                .bind_mount(&logdir, "/var/log/suricata"),
            self.context
                .manager
                .bind_mount(&libdir, "/var/lib/suricata"),
            self.context
                .manager
                .bind_mount(&rundir, "/var/run/suricata"),
        ];
        volumes
    }

    pub(crate) fn run(&self) -> RunCommandBuilder {
        let mut builder = RunCommandBuilder::new(
            self.context.manager,
            self.context.image_name(Container::Suricata),
        );
        builder.volumes(&self.volumes());
        builder
    }
}

pub(crate) struct RunCommandBuilder {
    manager: ContainerManager,
    image: String,
    rm: bool,
    it: bool,
    volumes: Vec<String>,
    name: Option<String>,
    args: Vec<String>,
    user: Option<String>,
}

impl RunCommandBuilder {
    pub(crate) fn new(manager: ContainerManager, image: impl ToString) -> Self {
        Self {
            manager,
            image: image.to_string(),
            rm: false,
            it: false,
            volumes: vec![],
            name: None,
            args: vec![],
            user: None,
        }
    }

    pub(crate) fn rm(&mut self) -> &mut Self {
        self.rm = true;
        self
    }

    pub(crate) fn it(&mut self) -> &mut Self {
        self.it = true;
        self
    }

    pub(crate) fn args(&mut self, args: &[impl ToString]) -> &mut Self {
        for arg in args {
            self.args.push(arg.to_string());
        }
        self
    }

    pub(crate) fn volumes(&mut self, volumes: &[impl ToString]) -> &mut Self {
        for volume in volumes {
            self.volumes.push(volume.to_string());
        }
        self
    }

    pub(crate) fn build(&self) -> Command {
        let mut command = self.manager.command();
        command.arg("run");
        if self.it {
            command.arg("-it");
        }
        if self.rm {
            command.arg("--rm");
        }
        if let Some(name) = &self.name {
            command.arg(format!("--name={}", name));
        }
        for volume in &self.volumes {
            command.arg(format!("--volume={}", volume));
        }
        if let Some(user) = &self.user {
            command.arg(format!("--user={}", user));
        }
        command.arg(&self.image);
        command.args(&self.args);
        command
    }
}

#[cfg(test)]
mod tests {
    use super::format_bind_mount;
    use std::path::Path;

    #[test]
    fn bind_mount_without_selinux_has_no_label_option() {
        assert_eq!(
            format_bind_mount(Path::new("/host/data"), "/data", &[], false),
            "/host/data:/data"
        );
    }

    #[test]
    fn bind_mount_with_selinux_uses_shared_label() {
        assert_eq!(
            format_bind_mount(Path::new("/host/data"), "/data", &[], true),
            "/host/data:/data:z"
        );
    }

    #[test]
    fn bind_mount_combines_selinux_and_runtime_options() {
        assert_eq!(
            format_bind_mount(Path::new("/host/data"), "/data", &["U"], true),
            "/host/data:/data:U,z"
        );
    }
}
