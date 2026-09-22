use acir::SerializationFormat;
use acir::circuit::Program;
use barretenberg_rs::BarretenbergApi;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::generated_types::CircuitComputeVkResponse;
use barretenberg_rs::generated_types::ProofSystemSettings;
use barretenberg_rs::generated_types::{CircuitInput, CircuitInputNoVK};
use barretenberg_rs::generated_types::CircuitProveResponse;
use barretenberg_rs::generated_types::CircuitVerifyResponse;
use barretenberg_rs::BarretenbergError;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use nargo::foreign_calls::transcript::ReplayForeignCallExecutor;
use nargo::foreign_calls::{DefaultForeignCallBuilder, layers};
use noir_artifact_cli::Artifact;
use noir_artifact_cli::execution::ExecutionResults;
use noir_artifact_cli::execution::ReturnValues;
use noirc_abi::InputMap;
use noirc_artifacts::program::CompiledProgram;
use std::io::Read;
use std::path::PathBuf;
use barretenberg_rs::Backend;

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

/// Representation of Barretenberg circuit
#[derive(Debug, Clone)]
pub struct BarretenbergCircuit {
    /// The aggregation circuit
    pub circuit: CompiledProgram,
    /// The response from computing the verification key
    pub compute_vk_response: CircuitComputeVkResponse,
    /// Settings to use for proving
    pub proof_system_settings: ProofSystemSettings,
    /// Name of the aggregation circuit
    pub circuit_name: String,
    /// Bytecode of the aggregation circuit
    pub program_bytecode: Vec<u8>,
}

impl BarretenbergCircuit {
    /// Load up the aggregation circuit from disk
    pub fn new<B: Backend>(api: &mut BarretenbergApi<B>, program_artifact_path: PathBuf) -> Self {
        let artifact_name = program_artifact_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let circuit_name = artifact_name.to_string();
        // Load up the aggregation circuit from disk
        let artifact = Artifact::read_from_file(&program_artifact_path).unwrap();
        let Artifact::Program(program) = artifact else {
            panic!("incorrect artifact type")
        };
        let circuit = CompiledProgram::from(program);
        // Grab the compressed program bytecode from the circuit
        let compressed_program_bytecode = Program::serialize_program_with_format(
            &circuit.program,
            SerializationFormat::default(),
        );

        // Decompress program bytecode
        let mut gz_decoder = flate2::read::GzDecoder::new(&*compressed_program_bytecode);
        let mut program_bytecode = Vec::new();
        gz_decoder.read_to_end(&mut program_bytecode).unwrap();

        // Proof system settings to use for generating the verification key
        let proof_system_settings = ProofSystemSettings {
            ipa_accumulation: false,
            oracle_hash_type: "poseidon2".to_string(),
            disable_zk: true,
            optimized_solidity_verifier: false,
        };
        // The circuit to generate a verification key for
        let circuit_input = CircuitInputNoVK {
            name: circuit_name.clone(),
            bytecode: program_bytecode.clone(),
        };
        // Compute the verification key
        let compute_vk_response = api
            .circuit_compute_vk(circuit_input, proof_system_settings.clone())
            .unwrap();
        Self {
            circuit,
            compute_vk_response,
            proof_system_settings,
            circuit_name,
            program_bytecode,
        }
    }

    /// Prove that the given inputs satisfy the circuit
    pub fn circuit_prove<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        input_map: InputMap,
    ) -> Result<CircuitProveResponse, BarretenbergError> {
        let expected_return = None;
        let initial_witness = self
            .circuit
            .abi
            .encode(&input_map, None)
            .expect("unable to encode initial witness");

        // Construct foreign call executor for circuit execution
        let transcript_executor: layers::Either<ReplayForeignCallExecutor<_>, _> =
            layers::Either::Right(layers::Unhandled);

        let mut foreign_call_executor = DefaultForeignCallBuilder {
            output: std::io::stdout(),
            enable_mocks: false,
            resolver_url: None,
            root_path: None,
            package_name: None,
        }
        .build_with_base(transcript_executor);
        // Execute the circuit on the given inputs
        let blackbox_solver = Bn254BlackBoxSolver;
        let witness_stack = nargo::ops::execute_program(
            &self.circuit.program,
            initial_witness,
            &blackbox_solver,
            &mut foreign_call_executor,
        )
        .expect("circuit execution error");
        // Extract certain witnesses from the stack
        let main_witness = &witness_stack
            .peek()
            .expect("Should have at least one witness on the stack")
            .witness;

        let (_, actual_return) = self
            .circuit
            .abi
            .decode(main_witness)
            .expect("unable to decode main witness");
        let results = ExecutionResults {
            witness_stack,
            return_values: ReturnValues {
                actual_return,
                expected_return,
            },
        };
        // Extract the execution witness
        let compressed_witness_bytes = results
            .witness_stack
            .serialize()
            .expect("output witness creation failed");

        // Decompress witness bytes
        let mut gz_decoder = flate2::read::GzDecoder::new(&*compressed_witness_bytes);
        let mut witness_bytes = Vec::new();
        gz_decoder.read_to_end(&mut witness_bytes).unwrap();
        // The circuit to generate a proof from
        let circuit_input = CircuitInput {
            name: self.circuit_name.clone(),
            bytecode: self.program_bytecode.clone(),
            verification_key: self.compute_vk_response.bytes.clone(),
        };
        // Compute the proof from the witness bytes
        api.circuit_prove(
            circuit_input,
            &witness_bytes,
            self.proof_system_settings.clone(),
        )
    }

    /// Verify that the given public inputs and proof satisfy the circuit
    pub fn circuit_verify<B: Backend>(
        &mut self,
        api: &mut BarretenbergApi<B>,
        prove_response: CircuitProveResponse,
    ) -> Result<CircuitVerifyResponse, BarretenbergError> {
        api.circuit_verify(
            &self.compute_vk_response.bytes,
            prove_response.public_inputs,
            prove_response.proof,
            self.proof_system_settings.clone(),
        )
    }
}

/// Write the given bytes into the given buffer at the given offset
pub fn write_bytes(dest: &mut [u8], offset: &mut usize, src: &[u8]) {
    let next_offset = *offset + src.len();
    dest[*offset..next_offset].copy_from_slice(src);
    *offset = next_offset;
}

/// Read bytes from the given buffer at the given offset
pub fn read_bytes<const N: usize>(src: &[u8], offset: &mut usize) -> [u8; N] {
    let mut dest = [0u8; N];
    let next_offset = *offset + N;
    dest.copy_from_slice(&src[*offset..next_offset]);
    *offset = next_offset;
    dest
}
