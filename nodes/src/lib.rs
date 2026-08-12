use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::BarretenbergApi;

/// The directory containing the common reference string
const CRS_DIR: &str = ".bb-crs";
/// Name of file containing G1 point data
const G1_UNCOMPRESSED_DATA_PATH: &str = "bn254_g1.dat";
/// Name of file containing G2 point data
const G2_UNCOMPRESSED_DATA_PATH: &str = "bn254_g2.dat";

/// Initialize the structured reference string
pub fn init_srs() {
    // Use the FFI backend which links directly to static libraries
    let backend = FfiBackend::new().unwrap();
    // Initialize the Barretenberg API
    let mut api = BarretenbergApi::new(backend);
    const NUM_POINTS: u32 = 1 << 24;
    // CRS parameters are stored relative to home directory
    let home_dir = std::env::home_dir().expect("unable to get home directory");
    // Sub-directory of the home directory containing the CRS parameters
    let crs_path = home_dir.join(CRS_DIR);
    // Read G1 point data
    let g1_data =
        std::fs::read(crs_path.join(G1_UNCOMPRESSED_DATA_PATH)).expect("unable to read G1 data");
    // Read G2 point data
    let g2_data =
        std::fs::read(crs_path.join(G2_UNCOMPRESSED_DATA_PATH)).expect("unable to read G2 data");
    // Initialize the global CRS
    let init_srs_response = api
        .srs_init_srs(&g1_data, NUM_POINTS, &g2_data)
        .expect("unable to initialize the global CRS");
    println!("Initialize SRS response: {:?}", init_srs_response);
    // Finally destroy the backend
    api.shutdown().unwrap();
}
