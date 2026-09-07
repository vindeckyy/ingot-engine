//! ingot — CLI client for the Ingot engine (docker CLI equivalent).

pub mod auth;
mod client;
mod commands;
mod compose;
mod ports;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ingot",
    about = "Ingot: a Docker-compatible container engine",
    version,
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[arg(long, global = true)]
    host: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show engine and client version
    Version,
    /// Ping the daemon
    Ping,
    /// Display system-wide information
    Info,
    /// Run a command in a new container
    Run {
        /// Run in background
        #[arg(short = 'd', long)]
        detach: bool,
        /// Container name
        #[arg(long)]
        name: Option<String>,
        /// Publish a port host:container
        #[arg(short = 'p', long = "publish")]
        publish: Vec<String>,
        /// Environment KEY=VAL
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        /// Volume src:dst
        #[arg(short = 'v', long = "volume")]
        volume: Vec<String>,
        /// Network mode
        #[arg(long, default_value = "default")]
        network: String,
        /// Allocate a TTY
        #[arg(short = 't', long)]
        tty: bool,
        /// Keep STDIN open
        #[arg(short = 'i', long)]
        interactive: bool,
        /// Automatically remove on exit
        #[arg(long)]
        rm: bool,
        /// Working directory
        #[arg(short = 'w', long = "workdir")]
        workdir: Option<String>,
        /// Custom DNS server (repeatable)
        #[arg(long)]
        dns: Vec<String>,
        /// Custom DNS search domain (repeatable)
        #[arg(long = "dns-search")]
        dns_search: Vec<String>,
        /// Custom DNS option (repeatable)
        #[arg(long = "dns-opt", visible_alias = "dns-option")]
        dns_opt: Vec<String>,
        image: String,
        /// Command to run
        cmd: Vec<String>,
    },
    /// Pull an image from a registry
    Pull {
        image: String,
        /// Target platform (for example "linux/amd64"); defaults to the daemon's
        #[arg(long)]
        platform: Option<String>,
    },
    /// Store registry credentials for later pulls
    Login {
        /// Registry host (defaults to Docker Hub)
        #[arg(default_value = "docker.io")]
        server: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        /// Read the password from stdin (scriptable)
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove stored registry credentials
    Logout {
        /// Registry host (defaults to Docker Hub)
        #[arg(default_value = "docker.io")]
        server: String,
    },
    /// List containers
    #[command(alias = "container ls")]
    Ps {
        /// Show all containers (default shows just running)
        #[arg(short = 'a', long)]
        all: bool,
        /// Only display container IDs
        #[arg(short = 'q', long)]
        quiet: bool,
        /// Don't truncate the output
        #[arg(long)]
        no_trunc: bool,
        /// Filter values (e.g. "name=web", "status=running", "label=k=v")
        #[arg(short = 'f', long)]
        filter: Vec<String>,
    },
    /// List images
    #[command(alias = "image ls")]
    Images {
        /// Only display image IDs
        #[arg(short = 'q', long)]
        quiet: bool,
        /// Don't truncate the output
        #[arg(long)]
        no_trunc: bool,
        /// Filter values (e.g. "dangling=true", "reference=busybox", "label=k=v")
        #[arg(short = 'f', long)]
        filter: Vec<String>,
    },
    /// Stop one or more running containers
    Stop { containers: Vec<String> },
    /// Kill a running container
    Kill { container: String },
    /// Remove one or more containers
    Rm {
        /// Force removal of a running container
        #[arg(short = 'f', long)]
        force: bool,
        containers: Vec<String>,
    },
    /// Fetch the logs of a container
    Logs {
        container: String,
        /// Follow log output
        #[arg(short = 'f', long)]
        follow: bool,
        /// Number of lines to show from the end
        #[arg(long)]
        tail: Option<String>,
    },
    /// Run a command in a running container
    Exec {
        container: String,
        /// Keep STDIN open
        #[arg(short = 'i', long)]
        interactive: bool,
        /// Allocate a TTY
        #[arg(short = 't', long)]
        tty: bool,
        /// Command
        cmd: Vec<String>,
    },
    /// Check system requirements and engine health
    Doctor,
    /// Build an image from a Dockerfile
    Build {
        /// Name and optionally tag (repeatable)
        #[arg(short = 't', long = "tag")]
        tags: Vec<String>,
        /// Dockerfile name
        #[arg(short = 'f', long = "file", default_value = "Dockerfile")]
        dockerfile: String,
        /// Don't use cache
        #[arg(long)]
        no_cache: bool,
        /// Don't use cache for this stage (index or AS name, repeatable) or later stages
        #[arg(long = "no-cache-filter")]
        no_cache_filter: Vec<String>,
        /// Build secret (repeatable): id=name,src=path or id=name,env=VAR
        #[arg(long)]
        secret: Vec<String>,
        /// Quiet output
        #[arg(short = 'q', long)]
        quiet: bool,
        /// Build context directory
        path: String,
    },
    /// Docker Compose
    Compose {
        /// Compose file path
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
        /// Project name
        #[arg(short = 'p', long = "project-name")]
        project: Option<String>,
        #[command(subcommand)]
        action: ComposeSubcmd,
    },
    /// Remove one or more images
    Rmi {
        /// Force removal (even if tagged/in-use)
        #[arg(short = 'f', long)]
        force: bool,
        images: Vec<String>,
    },
    /// Tag an image
    Tag {
        /// Source image (name or id)
        source: String,
        /// Target reference (repo[:tag])
        target: String,
    },
    /// Copy files between a container and the local filesystem
    Cp {
        /// Source: `container:path` or a local path
        source: String,
        /// Destination: `container:path` or a local path
        dest: String,
    },
    /// Manage networks
    Network {
        #[command(subcommand)]
        action: NetworkSubcmd,
    },
    /// Manage volumes
    Volume {
        #[command(subcommand)]
        action: VolumeSubcmd,
    },
    /// Show daemon-wide information and reclaim space
    System {
        #[command(subcommand)]
        action: SystemSubcmd,
    },
    /// Generate shell completions
    Completions {
        /// Shell type (bash, zsh, fish, elvish, powershell)
        shell: String,
    },
}

#[derive(Subcommand)]
pub enum NetworkSubcmd {
    /// List networks
    Ls,
    /// Create a network
    Create {
        name: String,
        /// Subnet in CIDR form (e.g. 10.0.0.0/24)
        #[arg(long)]
        subnet: Option<String>,
        /// Gateway IP
        #[arg(long)]
        gateway: Option<String>,
        /// Restrict external access
        #[arg(long)]
        internal: bool,
        /// Set a label (key=value, repeatable)
        #[arg(long)]
        label: Vec<String>,
    },
    /// Remove one or more networks
    Rm { networks: Vec<String> },
    /// Display detailed network information
    Inspect { network: String },
    /// Connect a container to a network
    Connect {
        network: String,
        container: String,
        /// Container alias (repeatable)
        #[arg(long)]
        alias: Vec<String>,
    },
    /// Disconnect a container from a network
    Disconnect {
        network: String,
        container: String,
        /// Force disconnect
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Remove unused networks
    Prune,
}

#[derive(Subcommand)]
pub enum VolumeSubcmd {
    /// List volumes
    Ls,
    /// Create a volume
    Create {
        name: Option<String>,
        /// Set a label (key=value, repeatable)
        #[arg(long)]
        label: Vec<String>,
    },
    /// Remove one or more volumes
    Rm { volumes: Vec<String> },
    /// Display detailed volume information
    Inspect { volume: String },
    /// Remove unused volumes
    Prune,
}

#[derive(Subcommand)]
pub enum SystemSubcmd {
    /// Show disk usage (images, containers, volumes, build cache)
    Df,
    /// Remove unused data (stopped containers, dangling images, unused volumes/networks)
    Prune {
        /// Don't prompt for confirmation
        #[arg(short = 'f', long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ComposeSubcmd {
    /// Create and start containers
    Up {
        /// Run containers in the background
        #[arg(short = 'd', long)]
        detach: bool,
        /// Build images before starting containers
        #[arg(long)]
        build: bool,
    },
    /// Stop and remove containers, networks
    Down {
        /// Remove named volumes declared in the volumes section
        #[arg(short = 'v', long = "volumes")]
        volumes: bool,
    },
    /// List containers for project
    Ps {
        /// Show all stopped and running containers
        #[arg(short = 'a', long)]
        all: bool,
    },
    /// View output from containers
    Logs {
        /// Follow log output
        #[arg(short = 'f', long)]
        follow: bool,
        /// Service name(s)
        services: Vec<String>,
    },
}

/// Decode a docker multiplexed frame: [0]=stream, [1..4]=0, [4..8]=len BE.
pub fn demux(buf: &[u8]) -> (u8, &[u8]) {
    if buf.len() < 8 {
        return (1, buf);
    }
    let stream = buf[0];
    let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let end = (8 + len).min(buf.len());
    (stream, &buf[8..end])
}

#[derive(Clone, Default)]
pub struct RunOpts {
    pub detach: bool,
    pub name: Option<String>,
    pub publish: Vec<String>,
    pub env: Vec<String>,
    pub volume: Vec<String>,
    pub network: String,
    pub tty: bool,
    pub interactive: bool,
    pub rm: bool,
    pub workdir: Option<String>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_opt: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // completions doesn't need a daemon connection.
    if let Cmd::Completions { shell } = &cli.cmd {
        return print_completions(shell);
    }

    let socket = match &cli.host {
        Some(h) => std::path::PathBuf::from(h.trim_start_matches("unix://")),
        None => client::default_socket(),
    };
    let api = client::ApiClient::connect(&socket)?;

    match cli.cmd {
        Cmd::Version => commands::version(&api).await,
        Cmd::Ping => {
            let text = api.get_text("/_ping").await?;
            println!("{text}");
            Ok(())
        }
        Cmd::Info => commands::info(&api).await,
        Cmd::Run {
            image,
            detach,
            name,
            publish,
            env,
            volume,
            network,
            tty,
            interactive,
            rm,
            workdir,
            dns,
            dns_search,
            dns_opt,
            cmd,
        } => {
            let opts = RunOpts {
                detach,
                name,
                publish,
                env,
                volume,
                network,
                tty,
                interactive,
                rm,
                workdir,
                dns,
                dns_search,
                dns_opt,
            };
            commands::run(&api, &opts, &image, cmd).await
        }
        Cmd::Pull { image, platform } => commands::pull(&api, &image, platform.as_deref()).await,
        Cmd::Login {
            server,
            username,
            password,
            password_stdin,
        } => {
            commands::login(
                &server,
                username.as_deref(),
                password.as_deref(),
                password_stdin,
            )
            .await
        }
        Cmd::Logout { server } => commands::logout(&server).await,
        Cmd::Ps {
            all,
            quiet,
            no_trunc,
            filter,
        } => commands::ps(&api, all, quiet, no_trunc, &filter).await,
        Cmd::Images {
            quiet,
            no_trunc,
            filter,
        } => commands::images(&api, quiet, no_trunc, &filter).await,
        Cmd::Stop { containers } => commands::stop(&api, &containers).await,
        Cmd::Kill { container } => commands::kill(&api, &container).await,
        Cmd::Rm { force, containers } => commands::rm(&api, force, &containers).await,
        Cmd::Logs {
            container,
            follow,
            tail,
        } => commands::logs(&api, &container, follow, tail).await,
        Cmd::Exec {
            container,
            interactive,
            tty,
            cmd,
        } => commands::exec(&api, &container, interactive, tty, cmd).await,
        Cmd::Build {
            tags,
            dockerfile,
            no_cache,
            no_cache_filter,
            secret,
            quiet,
            path,
        } => {
            let mut secrets = Vec::with_capacity(secret.len());
            for spec in &secret {
                secrets.push(commands::parse_secret_spec(spec)?);
            }
            commands::build(
                &api,
                &tags,
                &dockerfile,
                no_cache,
                &no_cache_filter,
                &secrets,
                quiet,
                &path,
            )
            .await
        }
        Cmd::Compose {
            file,
            project,
            action,
        } => match action {
            ComposeSubcmd::Up { detach, build } => {
                compose::up(&api, file.as_deref(), project.as_deref(), detach, build).await
            }
            ComposeSubcmd::Down { volumes } => {
                compose::down(&api, file.as_deref(), project.as_deref(), volumes).await
            }
            ComposeSubcmd::Ps { all } => {
                compose::ps(&api, file.as_deref(), project.as_deref(), all).await
            }
            ComposeSubcmd::Logs { follow, services } => {
                compose::logs(&api, file.as_deref(), project.as_deref(), follow, &services).await
            }
        },
        Cmd::Rmi { force, images } => commands::rmi(&api, force, &images).await,
        Cmd::Tag { source, target } => commands::tag(&api, &source, &target).await,
        Cmd::Cp { source, dest } => commands::cp(&api, &source, &dest).await,
        Cmd::Network { action } => match action {
            NetworkSubcmd::Ls => commands::network_ls(&api).await,
            NetworkSubcmd::Create {
                name,
                subnet,
                gateway,
                internal,
                label,
            } => {
                commands::network_create(
                    &api,
                    &name,
                    subnet.as_deref(),
                    gateway.as_deref(),
                    internal,
                    &label,
                )
                .await
            }
            NetworkSubcmd::Rm { networks } => commands::network_rm(&api, &networks).await,
            NetworkSubcmd::Inspect { network } => commands::network_inspect(&api, &network).await,
            NetworkSubcmd::Connect {
                network,
                container,
                alias,
            } => commands::network_connect(&api, &network, &container, &alias).await,
            NetworkSubcmd::Disconnect {
                network,
                container,
                force,
            } => commands::network_disconnect(&api, &network, &container, force).await,
            NetworkSubcmd::Prune => commands::network_prune(&api).await,
        },
        Cmd::Volume { action } => match action {
            VolumeSubcmd::Ls => commands::volume_ls(&api).await,
            VolumeSubcmd::Create { name, label } => {
                commands::volume_create(&api, name.as_deref(), &label).await
            }
            VolumeSubcmd::Rm { volumes } => commands::volume_rm(&api, &volumes).await,
            VolumeSubcmd::Inspect { volume } => commands::volume_inspect(&api, &volume).await,
            VolumeSubcmd::Prune => commands::volume_prune(&api).await,
        },
        Cmd::System { action } => match action {
            SystemSubcmd::Df => commands::system_df(&api).await,
            SystemSubcmd::Prune { force } => commands::system_prune(&api, force).await,
        },
        Cmd::Doctor => commands::doctor(&api, &socket).await,
        Cmd::Completions { .. } => unreachable!(),
    }
}

fn print_completions(shell: &str) -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::{generate, Shell};
    let shell_kind = match shell.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "elvish" => Shell::Elvish,
        "powershell" | "powershell.exe" => Shell::PowerShell,
        other => anyhow::bail!(
            "unknown shell '{other}': expected bash, zsh, fish, elvish, or powershell"
        ),
    };
    let mut cmd = Cli::command();
    generate(shell_kind, &mut cmd, "ingot", &mut std::io::stdout());
    Ok(())
}
