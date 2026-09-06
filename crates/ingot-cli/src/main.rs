//! ingot — CLI client for the Ingot engine (docker CLI equivalent).

mod client;
mod commands;
mod compose;

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
        image: String,
        /// Command to run
        cmd: Vec<String>,
    },
    /// Pull an image from a registry
    Pull { image: String },
    /// List containers
    #[command(alias = "container ls")]
    Ps {
        /// Show all containers (default shows just running)
        #[arg(short = 'a', long)]
        all: bool,
    },
    /// List images
    #[command(alias = "image ls")]
    Images,
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
        /// Command
        cmd: Vec<String>,
    },
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

/// Extract the Run variant's options (clap keeps them only inside the enum).
fn cli_run(cmd: &Cmd) -> RunOpts {
    if let Cmd::Run {
        detach, name, publish, env, volume, network, tty, interactive, rm, workdir, ..
    } = cmd
    {
        RunOpts {
            detach: *detach,
            name: name.clone(),
            publish: publish.clone(),
            env: env.clone(),
            volume: volume.clone(),
            network: network.clone(),
            tty: *tty,
            interactive: *interactive,
            rm: *rm,
            workdir: workdir.clone(),
        }
    } else {
        unreachable!()
    }
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
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
            image, detach, name, publish, env, volume, network, tty, interactive, rm, workdir, cmd,
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
            };
            commands::run(&api, &opts, &image, cmd).await
        }
        Cmd::Pull { image } => commands::pull(&api, &image).await,
        Cmd::Ps { all } => commands::ps(&api, all).await,
        Cmd::Images => commands::images(&api).await,
        Cmd::Stop { containers } => commands::stop(&api, &containers).await,
        Cmd::Kill { container } => commands::kill(&api, &container).await,
        Cmd::Rm { force, containers } => commands::rm(&api, force, &containers).await,
        Cmd::Logs { container, follow, tail } => commands::logs(&api, &container, follow, tail).await,
        Cmd::Exec { container, cmd } => commands::exec(&api, &container, cmd).await,
        Cmd::Build { tags, dockerfile, no_cache, quiet, path } => {
            commands::build(&api, &tags, &dockerfile, no_cache, quiet, &path).await
        }
        Cmd::Compose { file, project, action } => match action {
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
    }
}
