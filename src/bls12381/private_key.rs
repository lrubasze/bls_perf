use super::*;
use blst::min_pk::SecretKey;

pub struct Bls12381G1PrivateKey(SecretKey);

impl Bls12381G1PrivateKey {
    pub const LENGTH: usize = 32;

    pub fn public_key(&self) -> Bls12381G1PublicKey {
        Bls12381G1PublicKey(self.0.sk_to_pk().to_bytes())
    }

    pub fn sign_v1(&self, message: &[u8]) -> Bls12381G2Signature {
        let signature = self.0.sign(message, BLS12381_CIPHERSITE_V1, &[]).to_bytes();
        Bls12381G2Signature(signature)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, ()> {
        if slice.len() != Bls12381G1PrivateKey::LENGTH {
            return Err(());
        }
        Ok(Self(SecretKey::from_bytes(slice).map_err(|_| ())?))
    }

    pub fn from_u64(n: u64) -> Result<Self, ()> {
        let mut bytes = [0u8; Bls12381G1PrivateKey::LENGTH];
        (&mut bytes[Bls12381G1PrivateKey::LENGTH - 8..Bls12381G1PrivateKey::LENGTH])
            .copy_from_slice(&n.to_be_bytes());

        Ok(Self(SecretKey::from_bytes(&bytes).map_err(|_| ())?))
    }
}
pub fn get_aggregate_verify_test_data(
    cnt: u32,
    msg_cnt: u32,
    msg_size: usize,
) -> (
    Vec<Bls12381G1PrivateKey>,
    Vec<Bls12381G1PublicKey>,
    Vec<Vec<u8>>,
    Vec<Bls12381G2Signature>,
) {
    let sks: Vec<Bls12381G1PrivateKey> = (1..(cnt + 1))
        .map(|i| Bls12381G1PrivateKey::from_u64(i.into()).unwrap())
        .collect();

    let (msgs, sigs): (Vec<Vec<u8>>, Vec<Bls12381G2Signature>) = if msg_cnt == cnt {
        let msgs: Vec<Vec<u8>> = (1..(cnt + 1))
            .map(|i| {
                let u: u8 = (i % u8::MAX as u32) as u8;
                vec![u; msg_size]
            })
            .collect();
        let sigs: Vec<Bls12381G2Signature> = sks
            .iter()
            .zip(msgs.clone())
            .map(|(sk, msg)| sk.sign_v1(&msg))
            .collect();
        (msgs, sigs)
    } else if msg_cnt == 1 {
        let msgs: Vec<Vec<u8>> = vec![vec![(msg_size % u8::MAX as usize) as u8; msg_size]];

        let sigs: Vec<Bls12381G2Signature> = sks.iter().map(|sk| sk.sign_v1(&msgs[0])).collect();
        (msgs, sigs)
    } else {
        panic!("msg_cnt {} might be equal to cnt {} or 1", msg_cnt, cnt);
    };

    let pks: Vec<Bls12381G1PublicKey> = sks.iter().map(|sk| sk.public_key()).collect();

    (sks, pks, msgs, sigs)
}
pub fn get_aggregate_verify_test_data2(
    msg_sizes: &[usize],
) -> (
    Vec<Bls12381G1PrivateKey>,
    Vec<Bls12381G1PublicKey>,
    Vec<Vec<u8>>,
    Vec<Bls12381G2Signature>,
) {
    let cnt = msg_sizes.len() as u64;
    let sks: Vec<Bls12381G1PrivateKey> = (1..(cnt + 1))
        .map(|i| Bls12381G1PrivateKey::from_u64(i).unwrap())
        .collect();

    let msgs: Vec<Vec<u8>> = msg_sizes
        .iter()
        .map(|size| {
            let u: u8 = (size % u8::MAX as usize) as u8;
            vec![u; *size]
        })
        .collect();

    let sigs: Vec<Bls12381G2Signature> = sks
        .iter()
        .zip(msgs.clone())
        .map(|(sk, msg)| sk.sign_v1(&msg))
        .collect();

    let pks: Vec<Bls12381G1PublicKey> = sks.iter().map(|sk| sk.public_key()).collect();

    (sks, pks, msgs, sigs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let test_sk = "408157791befddd702672dcfcfc99da3512f9c0ea818890fcb6ab749580ef2cf";
        let test_pk = "93b1aa7542a5423e21d8e84b4472c31664412cc604a666e9fdf03baf3c758e728c7a11576ebb01110ac39a0df95636e2";
        let test_message_hash = hash("Test").as_bytes().to_vec();
        let test_signature = "8b84ff5a1d4f8095ab8a80518ac99230ed24a7d1ec90c4105f9c719aa7137ed5d7ce1454d4a953f5f55f3959ab416f3014f4cd2c361e4d32c6b4704a70b0e2e652a908f501acb54ec4e79540be010e3fdc1fbf8e7af61625705e185a71c884f1";
        let sk = Bls12381G1PrivateKey::from_bytes(&hex::decode(test_sk).unwrap()).unwrap();
        let pk = Bls12381G1PublicKey::from_str(test_pk).unwrap();
        let sig = Bls12381G2Signature::from_str(test_signature).unwrap();

        assert_eq!(sk.public_key(), pk);
        assert_eq!(sk.sign_v1(&test_message_hash), sig);
        assert!(verify_bls12381_v1(&test_message_hash, &pk, &sig));
    }

    #[test]
    fn sign_and_verify_aggregated_multiple_messages() {
        let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data(10, 10, 10);

        // Aggregate the signature
        let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

        let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
            pks.iter().zip(msgs).map(|(pk, sk)| (*pk, sk)).collect();

        // Verify the messages against public keys and aggregated signature
        assert!(aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig));
    }

    #[test]
    fn sign_and_verify_aggregated_single_message() {
        let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data(1, 1, 10);

        // Aggregate the signature (in fact it does not make sense to aggregate one signature)
        let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

        // Aggregated signature of one signature must be the same
        assert_eq!(agg_sig, sigs[0]);

        let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
            pks.iter().zip(msgs).map(|(pk, sk)| (*pk, sk)).collect();

        // Aggregate verify a single message over a single key and aggregated signature
        assert!(aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig));
    }

    #[test]
    fn sign_and_verify_aggregated_reverse_order() {
        let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data(10, 10, 10);

        // Aggregate the signature
        let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

        let mut msgs_rev = msgs.clone();
        msgs_rev.reverse();

        let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
            pks.iter().zip(msgs_rev).map(|(pk, sk)| (*pk, sk)).collect();

        // Verify the messages in reversed order against public keys and aggregated signature
        assert_eq!(
            aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig),
            false
        );
    }

    #[test]
    fn sign_and_verify_aggregated_missing_message() {
        let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data(10, 10, 10);

        // Aggregate the signature
        let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

        // Skip the last key and message tuple
        let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> = pks
            .iter()
            .zip(msgs)
            .take(9)
            .map(|(pk, sk)| (*pk, sk))
            .collect();

        // Verify the incomplete messages against public keys and aggregated
        // signature from all messages
        assert_eq!(
            aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig),
            false
        );

        // Aggregate the signatures from incomplete messages
        let agg_sig = Bls12381G2Signature::aggregate(&sigs[0..9]).unwrap();
        // Verify the incomplete messages against public keys and aggregated
        // signature from incomplete messages
        assert!(aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig));
    }

    #[test]
    fn sign_and_verify_fast_aggregated() {
        let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data(10, 1, 10);

        // Aggregate the signature
        let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

        // Verify the message against public keys and aggregated signature
        assert!(fast_aggregate_verify_bls12381_v1(
            msgs[0].as_slice(),
            &pks,
            &agg_sig
        ));
    }
}
