pragma circom 2.1.6;

template Poseidon2_2_5() {
    // Poseidon2 parameters: t=2, d=5, RF=8, RP=56
    signal input inputs[2];
    signal output out;

    var d = 5;
    var RF = 8;
    var RP = 56;
    var TOTAL_ROUNDS = RF + RP;

    // Simplified round constants
    var c[TOTAL_ROUNDS];
    for (var i = 0; i < TOTAL_ROUNDS; i++) {
        c[i] = i + 1;
    }

    // Simple MDS matrix
    var M[2][2] = [
        [1, 2],
        [3, 4]
    ];

    // Declare state and intermediate signals
    signal state0[TOTAL_ROUNDS + 1];
    signal state1[TOTAL_ROUNDS + 1];

    // intermediate variables for exponentiation and MDS
    signal s0_exp[TOTAL_ROUNDS];
    signal s1_exp[TOTAL_ROUNDS];
    signal s0_sq[TOTAL_ROUNDS];
    signal s0_qu[TOTAL_ROUNDS];
    signal s1_sq[TOTAL_ROUNDS];
    signal s1_qu[TOTAL_ROUNDS];

    signal t0[TOTAL_ROUNDS];
    signal t1[TOTAL_ROUNDS];

    // Initialize state
    state0[0] <== inputs[0];
    state1[0] <== inputs[1];

    for (var r = 0; r < TOTAL_ROUNDS; r++) {
        // === FULL ROUND (first and last 4 rounds) ===
        if (r < RF / 2 || r >= RF / 2 + RP) {
            // s0: (state0 + c)^5
            s0_sq[r] <== (state0[r] + c[r]) * (state0[r] + c[r]);
            s0_qu[r] <== s0_sq[r] * s0_sq[r];
            s0_exp[r] <== s0_qu[r] * (state0[r] + c[r]);

            s1_sq[r] <== (state1[r] + c[r]) * (state1[r] + c[r]);
            s1_qu[r] <== s1_sq[r] * s1_sq[r];
            s1_exp[r] <== s1_qu[r] * (state1[r] + c[r]);
        }
        // === PARTIAL ROUND ===
        else {
            s0_sq[r] <== (state0[r] + c[r]) * (state0[r] + c[r]);
            s0_qu[r] <== s0_sq[r] * s0_sq[r];
            s0_exp[r] <== s0_qu[r] * (state0[r] + c[r]);

            s1_exp[r] <== state1[r]; // no S-box
        }

        // === MDS linear layer ===
        t0[r] <== M[0][0] * s0_exp[r] + M[0][1] * s1_exp[r];
        t1[r] <== M[1][0] * s0_exp[r] + M[1][1] * s1_exp[r];

        state0[r + 1] <== t0[r];
        state1[r + 1] <== t1[r];
    }

    out <== state0[TOTAL_ROUNDS];
}
