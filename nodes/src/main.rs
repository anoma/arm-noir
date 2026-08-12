pub mod aggregator;

use crate::aggregator::BarretenbergAggregator;
use std::ops::RangeFrom;
use crate::aggregator::RecursiveAggregator;
use crate::aggregator::VerifierInputs;
use crate::aggregator::ThreadedAggregator;
use crate::aggregator::TcpAggregatorServer;
use crate::aggregator::Aggregator;
use nodes::init_srs;

/// Run a Barretenberg proof aggregator server with several threads
fn main() {
    type BarretenbergAggregatorT = BarretenbergAggregator<RangeFrom<usize>, RangeFrom<usize>>;
    type RecursiveAggregatorT =
        RecursiveAggregator<VerifierInputs, RangeFrom<usize>, RangeFrom<usize>>;
    // Initialize the structured reference string
    init_srs();
    // Grab the command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: aggregator <ADDRESS> <THREAD COUNT>");
        std::process::exit(1);
    }
    // The address at which the aggregator server will run
    let address = &args[1];
    // The number of aggregator threads to run
    let thread_count: usize = args[2].parse().expect("thread count should be a number");
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
