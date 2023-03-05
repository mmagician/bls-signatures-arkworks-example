# BLS verification with arkworks backend - example

This repository shows a simple example of how to use the [arkworks](https://github.com/arkworks-rs) framework for verifying BLS signatures.

# Parameters

It uses the BLS12-381 curve, a hashing domain `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` as specified in the [ethereum](https://github.com/ethereum/bls12-381-tests) repo, and assumes the zcash-like serialization.