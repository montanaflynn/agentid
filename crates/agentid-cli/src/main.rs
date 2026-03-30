use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentid")]
#[command(about = "AgentID - Signed Identity Grants for AI agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a local keystore
    Init,
    /// Manage agents
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
}

#[derive(Subcommand)]
enum AgentCommands {
    /// Generate a new agent keypair
    Create,
    /// List existing agents
    List,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("not yet implemented");
        }
        Commands::Agent { command } => match command {
            AgentCommands::Create => {
                println!("not yet implemented");
            }
            AgentCommands::List => {
                println!("not yet implemented");
            }
        },
    }
}
