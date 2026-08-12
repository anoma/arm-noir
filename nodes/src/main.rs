pub mod aggregator;

use crate::aggregator::BarretenbergAggregator;
use std::ops::RangeFrom;
use crate::aggregator::RecursiveAggregator;
use crate::aggregator::VerifierInputs;
use crate::aggregator::ThreadedAggregator;
use crate::aggregator::TcpAggregatorServer;
use crate::aggregator::Aggregator;
use std::net::ToSocketAddrs;
use nodes::init_srs;

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

/// Run the aggregator
fn main() {
    // Initialize the structured reference string
    init_srs();
    // Grab the command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: nodes <SUBCOMMAND> ...");
        std::process::exit(1);
    }
    match args[1].as_str() {
        "aggregator" => {
            if args.len() != 4 {
                eprintln!("Usage: nodes aggregator <ADDRESS> <THREAD COUNT>");
                std::process::exit(1);
            }
            // The address at which the aggregator server will run
            let address = &args[2];
            // The number of aggregator threads to run
            let thread_count = args[3].parse().expect("thread count should be a number");
            // Finally, start the aggregator server
            aggregator_server(address, thread_count);
        },
        _ => {
            eprintln!("Unknown subcommand, must be: aggregator");
            std::process::exit(1);
        }
    }
}
