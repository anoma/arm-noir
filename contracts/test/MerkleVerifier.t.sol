// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the contract we want to test. 
// Adjust the path to match your project structure.
import "../src/MerkleVerifier.sol"; 

contract MerkleVerifierTest is Test {
    MerkleVerifier public verifier;
    bytes32[128] public leaves7;
    bytes32[256] public leaves8;
    bytes32[512] public leaves9;
    bytes32[1024] public leaves10;
    bytes32 public expectedRoot7;
    bytes32 public expectedRoot8;
    bytes32 public expectedRoot9;
    bytes32 public expectedRoot10;

    function setUp() public {
        // 1. Deploy the verifier contract
        verifier = new MerkleVerifier();

        // 2. Populate the 128 leaves with mock data
        for (uint256 i = 0; i < leaves7.length; i++) {
            // Using a pseudo-random value for each leaf based on its index
            leaves7[i] = keccak256(abi.encodePacked("leaf", i));
        }

        // 2. Populate the 256 leaves with mock data
        for (uint256 i = 0; i < leaves8.length; i++) {
            // Using a pseudo-random value for each leaf based on its index
            leaves8[i] = keccak256(abi.encodePacked("leaf", i));
        }

        // 3. Populate the 512 leaves with mock data
        for (uint256 i = 0; i < leaves9.length; i++) {
            // Using a pseudo-random value for each leaf based on its index
            leaves9[i] = keccak256(abi.encodePacked("leaf", i));
        }

        // 4. Populate the 1024 leaves with mock data
        for (uint256 i = 0; i < leaves10.length; i++) {
            // Using a pseudo-random value for each leaf based on its index
            leaves10[i] = keccak256(abi.encodePacked("leaf", i));
        }

        // 5. Compute the expected Merkle root using a standard dynamic array approach
        expectedRoot7 = 0x04d6bdf04f7610049e54e0dfbfadab90c5dc232c87fbae931e8978702d0dfc2e;
        expectedRoot8 = 0x63ff9f93dab5222bd292ab385f22a0f9cfa66f61021ad6ef5b06062cfd46ad2e;
        expectedRoot9 = 0x4356829ac55cc6f104458e722af7d04db893a0c2c97ff14d6020555d6468ced7;
        expectedRoot10 = 0x23f94481907f3a6cc56f7a850f747a25d20aeb7a1fd987eb0a0cb93aa802fb94;
    }

    /**
     * @dev Tests that the contract correctly verifies a valid tree and root.
     */
    function test_VerifyRoot7_ValidRoot() public view {
        bool isValid = verifier.verifyRoot(leaves7, expectedRoot7);
        assertTrue(isValid, "The valid root should return true.");
    }

    /**
     * @dev Tests that the contract correctly verifies a valid tree and root.
     */
    function test_VerifyRoot8_ValidRoot() public view {
        bool isValid = verifier.verifyRoot(leaves8, expectedRoot8);
        assertTrue(isValid, "The valid root should return true.");
    }

    /**
     * @dev Tests that the contract correctly verifies a valid tree and root.
     */
    function test_VerifyRoot9_ValidRoot() public view {
        bool isValid = verifier.verifyRoot(leaves9, expectedRoot9);
        assertTrue(isValid, "The valid root should return true.");
    }

    /**
     * @dev Tests that the contract correctly verifies a valid tree and root.
     */
    function test_VerifyRoot10_ValidRoot() public view {
        bool isValid = verifier.verifyRoot(leaves10, expectedRoot10);
        assertTrue(isValid, "The valid root should return true.");
    }

    /**
     * @dev Tests that the contract rejects an incorrect expected root.
     */
    function test_VerifyRoot_InvalidRoot() public view {
        bytes32 wrongRoot = keccak256("totally wrong root");
        
        bool isValid = verifier.verifyRoot(leaves10, wrongRoot);
        assertFalse(isValid, "An invalid root should return false.");
    }

    /**
     * @dev Tests that mutating even a single leaf invalidates the computed root.
     */
    function test_VerifyRoot_InvalidLeaves() public view {
        // Create a copy of the valid leaves in memory
        bytes32[1024] memory tamperedLeaves = leaves10;
        
        // Tamper with one leaf (e.g., leaf at index 42)
        tamperedLeaves[42] = bytes32(uint256(999999999));

        bool isValid = verifier.verifyRoot(tamperedLeaves, expectedRoot10);
        assertFalse(isValid, "Tampered leaves should return false.");
    }
}
