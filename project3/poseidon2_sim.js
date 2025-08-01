function poseidon2_2_5(preimage) {
    const d = 5;
    const RF = 8;
    const RP = 56;
    const TOTAL_ROUNDS = RF + RP;

    // Round constants
    const c = Array.from({ length: TOTAL_ROUNDS }, (_, i) => BigInt(i + 1));

    // MDS matrix
    const M = [
        [1n, 2n],
        [3n, 4n]
    ];

    // Initial state: [preimage, capacity=0]
    let state = [BigInt(preimage), 0n];

    for (let r = 0; r < TOTAL_ROUNDS; r++) {
        let s = [0n, 0n];

        // Full rounds: both S-box
        if (r < RF / 2 || r >= RF / 2 + RP) {
            s[0] = pow(state[0] + c[r], d);
            s[1] = pow(state[1] + c[r], d);
        } else {
            // Partial rounds: only state[0]
            s[0] = pow(state[0] + c[r], d);
            s[1] = state[1];
        }

        // MDS layer
        const newState = [
            M[0][0] * s[0] + M[0][1] * s[1],
            M[1][0] * s[0] + M[1][1] * s[1]
        ];

        state = newState.map(x => x % PRIME); // optional: apply field modulus if needed
    }

    return state[0]; // output only first element
}

// Power function using BigInt
function pow(base, exp) {
    let result = 1n;
    for (let i = 0n; i < exp; i++) {
        result *= base;
    }
    return result;
}

// Optional: you can define a prime field here (like BN254's prime)
const PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Example usage
const preimage = 123n;
const hash = poseidon2_2_5(preimage);

console.log("Preimage:", preimage.toString());
console.log("Poseidon2 Hash:", hash.toString());

