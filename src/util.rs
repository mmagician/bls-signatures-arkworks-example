use ark_bls12_381::{G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use ark_std::fmt;
use std::io::Cursor;

/// This is an error that could occur during serialization
#[derive(Debug)]
pub enum VerificationError {
    InvalidSignature,
    InvalidData,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            VerificationError::InvalidSignature => write!(
                f,
                "The signature failed to verify on the provided public key!"
            ),
            VerificationError::InvalidData => write!(
                f,
                "The provided signature data could not be deserialized into a G2Affine point!"
            ),
        }
    }
}

impl ark_std::error::Error for VerificationError {}

pub(crate) fn g2_from_vec(vec: &[u8]) -> Result<G2Affine, VerificationError> {
    let serialized: [u8; 96] = vec.try_into().unwrap();
    let mut cursor = Cursor::new(&serialized[..]);
    // map the SerializationError to VerificationError::InvalidData
    G2Affine::deserialize_with_mode(&mut cursor, Compress::Yes, Validate::No)
        .map_err(|_| VerificationError::InvalidSignature)
}

pub(crate) fn g1_from_vec(vec: &[u8]) -> G1Affine {
    let serialized: [u8; 48] = vec.try_into().unwrap();
    let mut cursor = Cursor::new(&serialized[..]);
    // map the SerializationError to VerificationError::InvalidData
    G1Affine::deserialize_with_mode(&mut cursor, Compress::Yes, Validate::No).unwrap()
}
