use super::*;
use crate::perf;

/// Performs BLS12-381 G2 signature verification.
/// Domain specifier tag: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
pub fn verify_bls12381_v1(
    message: &[u8],
    public_key: &Bls12381G1PublicKey,
    signature: &Bls12381G2Signature,
) -> bool {
    if let Ok(sig) = blst::min_pk::Signature::from_bytes(&signature.0) {
        if let Ok(pk) = blst::min_pk::PublicKey::from_bytes(&public_key.0) {
            let result = sig.verify(true, message, BLS12381_CIPHERSITE_V1, &[], &pk, true);

            match result {
                blst::BLST_ERROR::BLST_SUCCESS => return true,
                _ => return false,
            }
        }
    }

    false
}

/// Local implementation of aggregated verify for no_std and WASM32 variants (no threads)
/// see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-coreaggregateverify
/// Inspired with blst::min_pk::Signature::aggregate_verify
fn aggregate_verify_bls12381_v1_no_threads(
    pub_keys_and_msgs: &[(Bls12381G1PublicKey, Vec<u8>)],
    signature: blst::min_pk::Signature,
) -> bool {
    // Below structs are copies of PublicKey and Signature
    // Redefining them to be able to access point field, which is private for PublicKey and Signature
    struct LocalPublicKey {
        point: blst::blst_p1_affine,
    }
    struct LocalSignature {
        point: blst::blst_p2_affine,
    }
    let mut pairing = blst::Pairing::new(true, BLS12381_CIPHERSITE_V1);

    // Aggregate
    let (result, _) = perf!("pairing_aggregate", {
        for (pk, msg) in pub_keys_and_msgs.iter() {
            if let Ok(pk) = blst::min_pk::PublicKey::from_bytes(&pk.0) {
                // transmute to LocalPublicKey to access point field
                let local_pk: LocalPublicKey = unsafe { core::mem::transmute(pk) };

                if pairing.aggregate(
                    &local_pk.point,
                    true,
                    &unsafe { core::ptr::null::<blst::blst_p2_affine>().as_ref() },
                    false,
                    msg,
                    &[],
                ) != blst::BLST_ERROR::BLST_SUCCESS
                {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    });
    if !result {
        return false;
    }

    let _ = perf!("pairing_commit", pairing.commit());

    let (result, _) = perf!(
        "validate",
        if let Err(_err) = signature.validate(false) {
            false
        } else {
            true
        }
    );
    if !result {
        return false;
    };

    // transmute to LocalSignature to access point field

    let (gtsig, _) = perf!("pairing_aggregated", {
        let local_sig: LocalSignature = unsafe { core::mem::transmute(signature) };
        let mut gtsig = blst::blst_fp12::default();
        blst::Pairing::aggregated(&mut gtsig, &local_sig.point);
        gtsig
    });

    let _ = perf!("pairing_verify", pairing.finalverify(Some(&gtsig)));
    true
}

/// Performs BLS12-381 G2 aggregated signature verification of
/// multiple messages each signed with different key.
/// Domain specifier tag: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
pub fn aggregate_verify_bls12381_v1(
    pub_keys_and_msgs: &[(Bls12381G1PublicKey, Vec<u8>)],
    signature: &Bls12381G2Signature,
) -> bool {
    if let (Ok(sig), _) = perf!(
        "sig_from_bytes",
        blst::min_pk::Signature::from_bytes(&signature.0)
    ) {
        aggregate_verify_bls12381_v1_no_threads(pub_keys_and_msgs, sig)
    } else {
        false
    }
}

pub fn aggregate_verify_bls12381_v1_threaded(
    pub_keys_and_msgs: &[(Bls12381G1PublicKey, Vec<u8>)],
    signature: &Bls12381G2Signature,
) -> bool {
    if let Ok(sig) = blst::min_pk::Signature::from_bytes(&signature.0) {
        {
            let mut pks = vec![];
            let mut msg_refs = vec![];
            for (pk, msg) in pub_keys_and_msgs.iter() {
                if let Ok(pk) = blst::min_pk::PublicKey::from_bytes(&pk.0) {
                    pks.push(pk);
                } else {
                    return false;
                }
                msg_refs.push(msg.as_slice());
            }
            let pks_refs: Vec<&blst::min_pk::PublicKey> = pks.iter().collect();

            let result =
                sig.aggregate_verify(true, &msg_refs, BLS12381_CIPHERSITE_V1, &pks_refs, true);

            matches!(result, blst::BLST_ERROR::BLST_SUCCESS)
        }
    } else {
        false
    }
}

/// Performs BLS12-381 G2 aggregated signature verification
/// one message signed with multiple keys.
/// Domain specifier tag: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
pub fn fast_aggregate_verify_bls12381_v1(
    message: &[u8],
    public_keys: &[Bls12381G1PublicKey],
    signature: &Bls12381G2Signature,
) -> bool {
    if let Ok(agg_pk) = Bls12381G1PublicKey::aggregate(public_keys) {
        return verify_bls12381_v1(message, &agg_pk, signature);
    }

    false
}

pub fn hash_to_g2(msg: &[u8]) {
    let mut q = blst::blst_p2::default();
    let aug: &[u8] = &[];
    //let mut sig_aff = blst::blst_p2_aff::default();
    //let mut sig_ser = [0u8; $sig_ser_size];
    unsafe {
        blst::blst_hash_to_g2(
            &mut q,
            msg.as_ptr(),
            msg.len(),
            BLS12381_CIPHERSITE_V1.as_ptr(),
            BLS12381_CIPHERSITE_V1.len(),
            aug.as_ptr(),
            aug.len(),
        );
    }
}
