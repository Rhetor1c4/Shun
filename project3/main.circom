pragma circom 2.1.6;

include "poseidon2_2_5.circom";

template Poseidon2Hash() {
    signal input preimage;
    signal input hash;     // 公开输入

    component h = Poseidon2_2_5();
    
    h.inputs[0] <== preimage;
    h.inputs[1] <== 0; // capacity element

    h.out === hash;
}

component main = Poseidon2Hash();

/* INPUT = {
    "preimage": "123",
    "hash": "19493495401281994609339738101762134063076316857794788563484127582357198466545"
} */