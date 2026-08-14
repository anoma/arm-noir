pub mod aggregator;
pub mod client;

use nodes::init_srs;
use clap::{Parser, Args, Subcommand};
use crate::aggregator::BarretenbergAggregator;
use std::ops::RangeFrom;
use crate::aggregator::RecursiveAggregator;
use crate::aggregator::VerifierInputs;
use crate::aggregator::ThreadedAggregator;
use crate::aggregator::TcpAggregatorServer;
use crate::aggregator::Aggregator;
use std::net::ToSocketAddrs;

/// Run a Barretenberg proof aggregator server with several threads
fn aggregator_server<B: ToSocketAddrs>(address: &B, thread_count: usize) {
    type BarretenbergAggregatorT = BarretenbergAggregator<RangeFrom<usize>, RangeFrom<usize>>;
    type RecursiveAggregatorT =
        RecursiveAggregator<VerifierInputs, RangeFrom<usize>, RangeFrom<usize>>;
    // Make a more complex aggregator
    let mut recursive_aggregator = RecursiveAggregatorT::new(0usize.., 0usize..);
    // Push thread_count sub-aggregators to actually handle the computations
    for _i in 0..thread_count {
        recursive_aggregator.insert_sub_aggregator(Box::new(ThreadedAggregator::new(
            0..,
            0..,
            || BarretenbergAggregatorT::new(0usize..),
        )));
    }
    // Build TCP aggregator server using the recursive aggregator
    let mut tcp_aggregator = TcpAggregatorServer::new(&address, recursive_aggregator);
    // Repeatedly accept new connections
    loop {
        if let Err(err) = tcp_aggregator.run() {
            println!("Encountered error in client connection: {:?}", err);
        }
    }
}

/// CLI interface for the UltraHonk based Anoma Resource Machine
#[derive(Parser)]
#[command(name = "nodes", version, about, long_about = None)]
enum Cli {
    /// Run the proof aggregator
    Aggregator(AggregatorArgs),
    /// Run the transfer client
    #[command(subcommand)]
    Client(ClientCommands),
}

#[derive(Args)]
struct AggregatorArgs {
    /// The address at which the aggregator server will run
    address: String,
    /// Number of aggregator threads to run
    thread_count: usize,
}

#[derive(Subcommand)]
enum ClientCommands {
    /// Effect a transparent, shielding, shielded, or unshielded transfer
    Transfer {
        /// URL of Ethereum RPC to connect to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Spending key or private key to send from
        #[arg(long)]
        from: String,
        /// Ethereum address or transparent address to send to
        #[arg(long)]
        to: String,
        /// The amount to be sent
        #[arg(long)]
        amount: u64,
        /// The shielded pool to submit transaction to
        #[arg(long)]
        pool: String,
        /// The Ethereum private key that signs the transaction. Defaults to from.
        #[arg(long)]
        signer: Option<String>,
    },
    /// Permit the Permit2 smart contract to spend the signer's tokens
    Approve {
        /// URL of Ethereum RPC to connect to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Address of the Permit2 contract
        #[arg(long)]
        spender: String,
        /// The address authorizing its tokens to be spent
        #[arg(long)]
        signer: String,
        /// The ERC20 token whose spending is being authorized
        #[arg(long)]
        token: String,
    },
}

/// Run the aggregator
fn main() {
    let cli = Cli::parse();
    // Initialize the structured reference string
    init_srs();
    // Process CLI arguments
    match cli {
        Cli::Aggregator(args) => {
            // Finally, start the aggregator server
            aggregator_server(&args.address, args.thread_count);
        },
        Cli::Client(cmds) => {
            // Client implementation...
        },
    }
}
