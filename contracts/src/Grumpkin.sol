// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.16;

import "forge-std/Test.sol";
import "src/Utilities.sol";

library Grumpkin {
    // The prime modulus of the finite field over which the Grumpkin curve is defined.
    uint256 public constant P_MOD = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    // The order of the base point of the Grumpkin elliptic curve.
    uint256 public constant R_MOD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    // Coefficient in the Grumpkin equation.
    uint256 public constant B = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffff0;

    struct GrumpkinAffinePoint {
        uint256 x;
        uint256 y;
    }

    struct GrumpkinProjectivePoint {
        uint256 x;
        uint256 y;
        uint256 z;
    }

    /**
     * @dev Defines the identity element (point at infinity) for the Grumpkin curve. The identity element is a special
     * point that acts as the 'zero' element in point addition.
     * @return The identity element represented in the curve's coordinate system.
     */
    function Identity() public pure returns (GrumpkinAffinePoint memory) {
        return GrumpkinAffinePoint(0, 0);
    }

    /**
     * @dev Adds two points on the Grumpkin curve.
     * @param p1 The first point to add.
     * @param p2 The second point to add.
     * @return p3 The result of adding p1 and p2, another point on the curve.
     */
    function add_projective(GrumpkinProjectivePoint memory p1, GrumpkinProjectivePoint memory p2)
        public
        pure
        returns (GrumpkinProjectivePoint memory)
    {
        uint256 x3;
        uint256 y3;
        uint256 z3;

        assembly {
            // Constants
            let P := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            let CONST_3B := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffce

            // Load variables straight from memory structs
            let x1 := mload(p1)
            let y1 := mload(add(p1, 0x20))
            let z1 := mload(add(p1, 0x40))

            let x2 := mload(p2)
            let y2 := mload(add(p2, 0x20))
            let z2 := mload(add(p2, 0x40))

            // Pure stack math (no memory arrays)
            let t0 := mulmod(x1, x2, P)
            let t1 := mulmod(y1, y2, P)
            let t2 := mulmod(z1, z2, P)

            let t3 := mulmod(addmod(x1, y1, P), addmod(x2, y2, P), P)
            let t4 := addmod(t0, t1, P)
            t3 := addmod(t3, sub(P, t4), P)

            t4 := mulmod(addmod(x1, z1, P), addmod(x2, z2, P), P)
            let t5 := addmod(t0, t2, P)
            t4 := addmod(t4, sub(P, t5), P)

            t5 := mulmod(addmod(y1, z1, P), addmod(y2, z2, P), P)
            x3 := addmod(t1, t2, P)
            t5 := addmod(t5, sub(P, x3), P)

            x3 := mulmod(t2, CONST_3B, P)
            z3 := x3 // Simplified from addmod(x3, 0, P)

            x3 := addmod(t1, sub(P, z3), P)
            z3 := addmod(t1, z3, P)
            y3 := mulmod(x3, z3, P)

            t1 := addmod(t0, t0, P)
            t1 := addmod(t1, t0, P)

            t4 := mulmod(t4, CONST_3B, P)
            // Skipped redundant t[2] = 0 math

            let t0_new := mulmod(t1, t4, P)
            y3 := addmod(y3, t0_new, P)

            let t0_new2 := mulmod(t5, t4, P)
            x3 := mulmod(t3, x3, P)
            x3 := addmod(x3, sub(P, t0_new2), P)

            let t0_new3 := mulmod(t3, t1, P)
            z3 := mulmod(t5, z3, P)
            z3 := addmod(z3, t0_new3, P)
        }

        return GrumpkinProjectivePoint(x3, y3, z3);
    }

    /**
     * @dev Checks if a given point on the Grumpkin curve is the identity element (point at infinity).
     * @param point The point to be checked.
     * @return True if the point is the identity element, false otherwise.
     */
    function is_identity(GrumpkinProjectivePoint memory point) public pure returns (bool) {
        return point.z == 0;
    }

    function to_projective(GrumpkinAffinePoint memory p1) public pure returns (GrumpkinProjectivePoint memory p2) {
        if (is_identity(p1)) {
            p2.x = 0;
            p2.y = 1;
            p2.z = 0;
        } else {
            p2.x = p1.x;
            p2.y = p1.y;
            p2.z = 1;
        }
        return p2;
    }

    /**
     * @dev Converts a point from projective to affine coordinates on the Grumpkin curve.
     * Affine coordinates are the common (x, y) representation, while projective coordinates add a third 'z'
     * coordinate for efficiency.
     * @param p1 The projective coordinates to be converted.
     * @return p2 The point in affine coordinates.
     */
    function to_affine(GrumpkinProjectivePoint memory p1) public view returns (GrumpkinAffinePoint memory p2) {
        require(p1.z != 0, "[Grumpkin::to_affine] can't invert zero");

        uint256 zinv = Field.invert(p1.z, R_MOD);
        uint256 x = mulmod(p1.x, zinv, R_MOD);
        uint256 y = mulmod(p1.y, zinv, R_MOD);
        return GrumpkinAffinePoint(x, y);
    }

    /**
     * @dev Adds two points on the Grumpkin curve.
     * @param p1 The first point to add.
     * @param p2 The second point to add.
     * @return The result of adding p1 and p2, another point on the curve.
     */
    function add(GrumpkinAffinePoint memory p1, GrumpkinAffinePoint memory p2)
        public
        view
        returns (GrumpkinAffinePoint memory)
    {
        GrumpkinProjectivePoint memory self = to_projective(p1);
        GrumpkinProjectivePoint memory rhs = to_projective(p2);

        if (is_identity(p1) && is_identity(p2)) {
            return Identity();
        }

        return to_affine(add_projective(self, rhs));
    }

    /**
     * @dev Checks if a given point on the Grumpkin curve is the identity element (point at infinity).
     * @param point The point to be checked.
     * @return True if the point is the identity element, false otherwise.
     */
    function is_identity(GrumpkinAffinePoint memory point) public pure returns (bool) {
        if (point.x != 0) {
            return false;
        }
        if (point.y != 0) {
            return false;
        }
        return true;
    }

    /**
     * @dev Converts a point from projective to affine coordinates on the Grumpkin curve.
     * Affine coordinates are the common (x, y) representation, while projective coordinates add a third 'z'
     * coordinate for efficiency.
     * @param x_input The x coordinate in projective coordinates to be converted.
     * @param y_input The y coordinate in projective coordinates to be converted.
     * @param z_input The z coordinate in projective coordinates to be converted.
     * @return The point in affine coordinates.
     */
    function to_affine(uint256 x_input, uint256 y_input, uint256 z_input) private view returns (uint256, uint256) {
        require(z_input != 0, "[Grumpkin::to_affine] can't invert zero");

        uint256 zinv = Field.invert(z_input, R_MOD);
        uint256 x = mulmod(x_input, zinv, R_MOD);
        uint256 y = mulmod(y_input, zinv, R_MOD);
        return (x, y);
    }

    /**
     * @dev Multiplies the curve coefficient B by 3 and applies it to a given scalar.
     * @param t The scalar to be multiplied.
     * @return The resulting point after multiplication.
     */
    function mul_by_3b(uint256 t) private pure returns (uint256) {
        // In Rust:
        //        static ref CONST_3B: $base = $constant_b + $constant_b + $constant_b;
        // In Solidity:
        //        uint256 const_b = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffff0;
        //        uint256 const_2b = addmod(const_b, const_b, Grumpkin.R_MOD);
        //        uint256 const_3b = addmod(const_2b, const_b, Grumpkin.R_MOD);
        return mulmod(t, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffce, R_MOD);
    }

    /**
     * @dev Negates a point on the Grumpkin curve. This operation inverts the point over the x-axis on the elliptic curve.
     * @param point The point on the Grumpkin curve to be negated.
     * @return The negated point, also on the Grumpkin curve.
     */
    function negate(GrumpkinAffinePoint memory point) public pure returns (GrumpkinAffinePoint memory) {
        return GrumpkinAffinePoint(point.x, P_MOD - (point.y % P_MOD));
    }

    /**
     * @dev Negates the base point of the Grumpkin curve. This is a specialized case of point negation for the curve's base point.
     * @param scalar The scalar value to be negated.
     * @return The negated base point on the Grumpkin curve.
     */
    function negateBase(uint256 scalar) internal pure returns (uint256) {
        return P_MOD - (scalar % P_MOD);
    }

    /**
     * @dev Negates a scalar value. This operation performs modular arithmetic negation of a scalar.
     * @param scalar The scalar value to be negated.
     * @return The negated scalar value.
     */
    function negateScalar(uint256 scalar) internal pure returns (uint256) {
        return R_MOD - (scalar % R_MOD);
    }

    /**
     * @dev Performs the point doubling operation on the Grumpkin curve.
     * @param point The point on the Grumpkin curve to be doubled.
     * @return The doubled point, another point on the curve.
     */
    function double(GrumpkinAffinePoint memory point) public view returns (GrumpkinAffinePoint memory) {
        if (is_identity(point)) {
            return point;
        }
        uint256 x = point.x;
        uint256 y = point.y;
        //uint256 z = 1;

        uint256 t0 = mulmod(x, x, R_MOD);
        uint256 t1 = mulmod(y, y, R_MOD);
        uint256 t2 = 1; // z * z = 1 * 1 = 1
        uint256 t3 = mulmod(x, y, R_MOD);
        t3 = addmod(t3, t3, R_MOD);
        uint256 z3 = x; // x * z = x * 1 = x
        z3 = addmod(z3, z3, R_MOD);
        uint256 x3 = 0; // since constant A = 0 in Grumpkin
        uint256 y3 = mul_by_3b(t2);
        y3 = addmod(x3, y3, R_MOD);
        x3 = addmod(t1, negateScalar(y3), R_MOD);
        y3 = addmod(t1, y3, R_MOD);
        y3 = mulmod(x3, y3, R_MOD);
        x3 = mulmod(t3, x3, R_MOD);
        z3 = mul_by_3b(z3);
        t2 = 0; // // since constant A = 0 in Grumpkin
        t3 = addmod(t0, negateScalar(t2), R_MOD);
        t3 = 0; // since constant A = 0 in Grumpkin
        t3 = addmod(t3, z3, R_MOD);
        z3 = addmod(t0, t0, R_MOD);
        t0 = addmod(z3, t0, R_MOD);
        t0 = addmod(t0, t2, R_MOD);
        t0 = mulmod(t0, t3, R_MOD);
        y3 = addmod(y3, t0, R_MOD);
        t2 = y; // y * z = y * 1 = y
        t2 = addmod(t2, t2, R_MOD);
        t0 = mulmod(t2, t3, R_MOD);
        x3 = addmod(x3, negateScalar(t0), R_MOD);
        z3 = mulmod(t2, t1, R_MOD);
        z3 = addmod(z3, z3, R_MOD);
        z3 = addmod(z3, z3, R_MOD);

        (x, y) = to_affine(x3, y3, z3);

        return GrumpkinAffinePoint(x, y);
    }

    /**
     * @dev Performs scalar multiplication on the Grumpkin curve.
     * @param point The point on the Grumpkin curve to be multiplied.
     * @param scalar The scalar by which to multiply the point.
     * @return The result of scalar multiplication, which is another point on the curve.
     */
    function scalarMul(GrumpkinAffinePoint memory point, uint256 scalar)
        public
        view
        returns (GrumpkinAffinePoint memory)
    {
        GrumpkinAffinePoint memory acc = Identity();

        bytes32 scalar_bytes = bytes32(scalar);
        for (uint256 byteIndex = 0; byteIndex < 32; byteIndex++) {
            for (uint256 bitIndex = 0; bitIndex < 8; bitIndex++) {
                acc = double(acc);
                if ((uint8(scalar_bytes[byteIndex] >> (7 - bitIndex)) & 1) == 1) {
                    acc = add(acc, point);
                }
            }
        }

        return acc;
    }

    function multiScalarMul(GrumpkinAffinePoint[] memory bases, uint256[] memory scalars)
        public
        view
        returns (GrumpkinAffinePoint memory r)
    {
        require(scalars.length == bases.length, "MSM error: length does not match");

        r = scalarMul(bases[0], scalars[0]);
        for (uint256 i = 1; i < scalars.length; i++) {
            r = add(r, scalarMul(bases[i], scalars[i]));
        }
    }

    /**
     * @dev This function converts the compressed Grumpkin point back into the full point representation.
     * @param compressed The compressed representation of the point.
     * @return The decompressed point on the Grumpkin curve.
     */
    function decompress(uint256 compressed) public view returns (GrumpkinAffinePoint memory) {
        uint8 is_inf = uint8(bytes32(compressed)[0]) >> 7;
        uint8 y_sign = uint8(bytes32(compressed)[0]) >> 6;
        y_sign &= 1;

        uint256 x = compressed & 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

        if ((x == 0) && (is_inf == 0)) {
            return Identity();
        }

        uint256 y;
        uint256 _mod = R_MOD;

        assembly {
            y := mulmod(x, x, _mod)
            y := mulmod(y, x, _mod)
            y := addmod(y, B, _mod)
        }

        y = Field.sqrt(y, _mod);

        uint8 sign = ((uint8(y & 0xff)) & 1);

        if ((y_sign ^ sign) == 1) {
            y = negateScalar(y);
        }

        return GrumpkinAffinePoint(x, y);
    }

    function getAt(uint256 segment, uint256 c, uint256 scalar) public returns (uint256) {
        uint256 skipBits = segment * c;
        if (skipBits >= 256) {
            return 0;
        }

        uint256 res = (scalar >> skipBits) % (1 << c);
        return res;
    }

    function multiScalarMulSerial(GrumpkinAffinePoint[] memory bases, uint256[] memory scalars)
        public
        returns (GrumpkinAffinePoint memory r)
    {
        require(scalars.length == bases.length, "MSM error: length does not match");

        uint256 c;
        if (bases.length < 4) {
            c = 1;
        } else if (bases.length < 32) {
            c = 3;
        } else {
            c = CommonUtilities.log2(bases.length);
        }

        GrumpkinAffinePoint[] memory buckets = new GrumpkinAffinePoint[]((1 << c) - 1);
        GrumpkinAffinePoint memory res = Identity();

        uint256 segments = (256 / c) + 1;
        for (uint256 segment = segments; segment > 0; segment--) {
            for (uint256 i = 0; i < c; i++) {
                res = double(res);
            }

            for (uint256 i = 0; i < buckets.length; i++) {
                buckets[i] = Identity();
            }

            for (uint256 i = 0; i < bases.length; i++) {
                uint256 limb = getAt(segment - 1, c, scalars[i]);
                if (limb != 0) {
                    buckets[limb - 1] = add(buckets[limb - 1], bases[i]);
                }
            }

            GrumpkinAffinePoint memory runningSum = Identity();
            for (uint256 i = buckets.length; i > 0; i--) {
                runningSum = add(buckets[i - 1], runningSum);
                res = add(res, runningSum);
            }
        }

        r = res;
    }
}
