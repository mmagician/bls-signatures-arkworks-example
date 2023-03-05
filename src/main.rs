use crate::util::{g1_from_vec, VerificationError};
use util::g2_from_vec;

mod util;
use ark_bls12_381::{
    g1::Config as G1Config, g2::Config as G2Config, Bls12_381, G1Affine, G2Affine,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    short_weierstrass::{Projective, SWCurveConfig},
};
use ark_ff::field_hashers::DefaultFieldHasher;
use hex_literal::hex;
use sha2::Sha256;

/// As per README in: https://github.com/ethereum/bls12-381-tests
const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub fn verify(pk: &G1Affine, message: &[u8], signature: &[u8]) -> Result<bool, VerificationError> {
    // G1 generator
    let p = G1Config::GENERATOR;

    // deserialize the signature into a G2Affine
    let r: G2Affine = g2_from_vec(signature)?;

    // hash the message to G2
    let g2_mapper = MapToCurveBasedHasher::<
        Projective<G2Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(DOMAIN)
    .unwrap();
    let q = g2_mapper.hash(message).unwrap();

    // check the pairing
    let c1 = Bls12_381::pairing(pk, q);
    let c2 = Bls12_381::pairing(p, r);
    Ok(c1 == c2)
}

fn main() {
    // example from verify_valid_case_195246ee3bd3b6ec.json from https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.1
    let pk_bytes: [u8; 48] = hex!("b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f");
    let message: [u8; 32] =
        hex!("abababababababababababababababababababababababababababababababab");
    let signature: [u8; 96] = hex!("ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9");

    let pk: G1Affine = g1_from_vec(&pk_bytes);
    let result = verify(&pk, &message, &signature).unwrap();

    assert!(result);
}
