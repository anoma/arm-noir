// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/console.sol";

contract MerkleVerifier {
    /**
     * @dev Computes the Merkle root of exactly 128 leaves and verifies it.
     * @param nodes An array of 128 bytes32 values.
     * @param expectedRoot The expected bytes32 Merkle root.
     * @return bool True if the computed root matches the expected root, false otherwise.
     */
    function verifyRoot(bytes32[128] memory nodes, bytes32 expectedRoot) public pure returns (bool) {
        // Step 1: Iteratively compute the parent nodes layer by layer.
        // A tree with 128 leaves will loop exactly 7 times (128 -> 64 -> 32 ... -> 1).
        uint256 count = nodes.length;

        while (count > 1) {
            count = count / 2;

            for (uint256 i = 0; i < count; i++) {
                bytes32 left = nodes[i * 2];
                bytes32 right = nodes[(i * 2) + 1];

                // Compute the parent hash.
                // NOTE: This uses strict positional ordering (left, then right).
                nodes[i] = keccak256(abi.encodePacked(left, right));
            }
        }

        // Step 2: The final remaining node at index 0 is the computed Merkle root.
        return nodes[0] == expectedRoot;
    }

    /**
     * @dev Computes the Merkle root of exactly 256 leaves and verifies it.
     * @param nodes An array of 256 bytes32 values.
     * @param expectedRoot The expected bytes32 Merkle root.
     * @return bool True if the computed root matches the expected root, false otherwise.
     */
    function verifyRoot(bytes32[256] memory nodes, bytes32 expectedRoot) public pure returns (bool) {
        // Step 1: Iteratively compute the parent nodes layer by layer.
        // A tree with 256 leaves will loop exactly 8 times (256 -> 128 -> 64 ... -> 1).
        uint256 count = nodes.length;

        while (count > 1) {
            count = count / 2;

            for (uint256 i = 0; i < count; i++) {
                bytes32 left = nodes[i * 2];
                bytes32 right = nodes[(i * 2) + 1];

                // Compute the parent hash.
                // NOTE: This uses strict positional ordering (left, then right).
                nodes[i] = keccak256(abi.encodePacked(left, right));
            }
        }

        // Step 2: The final remaining node at index 0 is the computed Merkle root.
        return nodes[0] == expectedRoot;
    }

    /**
     * @dev Computes the Merkle root of exactly 512 leaves and verifies it.
     * @param nodes An array of 512 bytes32 values.
     * @param expectedRoot The expected bytes32 Merkle root.
     * @return bool True if the computed root matches the expected root, false otherwise.
     */
    function verifyRoot(bytes32[512] memory nodes, bytes32 expectedRoot) public pure returns (bool) {
        // Step 1: Iteratively compute the parent nodes layer by layer.
        // A tree with 512 leaves will loop exactly 9 times (512 -> 256 -> 128 ... -> 1).
        uint256 count = nodes.length;

        while (count > 1) {
            count = count / 2;

            for (uint256 i = 0; i < count; i++) {
                bytes32 left = nodes[i * 2];
                bytes32 right = nodes[(i * 2) + 1];

                // Compute the parent hash.
                // NOTE: This uses strict positional ordering (left, then right).
                nodes[i] = keccak256(abi.encodePacked(left, right));
            }
        }

        // Step 2: The final remaining node at index 0 is the computed Merkle root.
        return nodes[0] == expectedRoot;
    }

    /**
     * @dev Computes the Merkle root of exactly 1024 leaves and verifies it.
     * @param nodes An array of 1024 bytes32 values.
     * @param expectedRoot The expected bytes32 Merkle root.
     * @return bool True if the computed root matches the expected root, false otherwise.
     */
    function verifyRoot(bytes32[1024] memory nodes, bytes32 expectedRoot) public pure returns (bool) {
        // Step 1: Iteratively compute the parent nodes layer by layer.
        // A tree with 1024 leaves will loop exactly 10 times (1024 -> 512 -> 256 ... -> 1).
        uint256 count = nodes.length;

        while (count > 1) {
            count = count / 2;

            for (uint256 i = 0; i < count; i++) {
                bytes32 left = nodes[i * 2];
                bytes32 right = nodes[(i * 2) + 1];

                // Compute the parent hash.
                // NOTE: This uses strict positional ordering (left, then right).
                nodes[i] = keccak256(abi.encodePacked(left, right));
            }
        }

        // Step 2: The final remaining node at index 0 is the computed Merkle root.
        return nodes[0] == expectedRoot;
    }
}
