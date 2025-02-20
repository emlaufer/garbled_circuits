use rand::thread_rng;
use rsa::{traits::PublicKeyParts, BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

use crate::io::{read_message, wait_for_message, wait_for_read, write_message};

pub struct OTSender {}

impl OTSender {
    pub fn send(msg0: &[u8], msg1: &[u8]) {
        wait_for_message("pks");
        let keys = deserialize_rsa_pks(&read_message());

        let (ct0, ct1) = alice_ot1([keys[0].clone(), keys[1].clone()], msg0, msg1);
        let cts = serde_json::to_string(&[ct0, ct1]).unwrap();
        write_message(cts.as_bytes(), "cts");
        wait_for_read("cts");
    }
}

pub struct OTReceiver {}

impl OTReceiver {
    pub fn receive(bit: usize) -> Vec<u8> {
        let ((b0, b1), sk) = bob_ot1(bit);
        write_message(serialize_rsa_pk(&[b0, b1]).as_bytes(), "pks");

        wait_for_message("cts");
        let serialized_cts = read_message();
        let cts: Vec<Vec<u8>> =
            serde_json::from_str(&String::from_utf8(serialized_cts).unwrap()).unwrap();

        bob_ot2(bit, sk, [cts[0].clone(), cts[1].clone()])
    }
}

// This should be ~2048, but to decrease key generation time
// I'll use 512
const RSA_SECURITY_LEVEL: usize = 512;

/// Helper to serialize RSA public keys
pub fn serialize_rsa_pk(pks: &[RsaPublicKey]) -> String {
    let mut nums = vec![];
    for pk in pks {
        nums.push(pk.n().to_bytes_be());
        nums.push(pk.e().to_bytes_be());
    }
    serde_json::to_string(&nums).unwrap()
}

/// Helper to deserialize RSA public keys
pub fn deserialize_rsa_pks(bytes: &[u8]) -> Vec<RsaPublicKey> {
    let bytes: Vec<Vec<u8>> =
        serde_json::from_str(&String::from_utf8(bytes.to_vec()).unwrap()).unwrap();

    let mut pks = vec![];
    for i in 0..bytes.len() / 2 {
        let n = &bytes[i * 2];
        let e = &bytes[i * 2 + 1];

        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        pks.push(RsaPublicKey::new(n, e).unwrap());
    }
    pks
}

pub fn bob_ot1(bit: usize) -> ((RsaPublicKey, RsaPublicKey), RsaPrivateKey) {
    let mut rng = thread_rng();
    let sk = RsaPrivateKey::new(&mut rng, RSA_SECURITY_LEVEL).unwrap();
    let pk = RsaPublicKey::from(&sk);

    // Generate related public keys, one for each possible bit
    // In reality, we need to use a hash function to generate the offset
    // Otherwise, the modulus may be insecure
    // But...I'll use their suggestion for a fixed offset
    let pk0 = if bit == 0 {
        pk.clone()
    } else {
        RsaPublicKey::new(pk.n() - BigUint::new(vec![2]), pk.e().clone()).unwrap()
    };
    let pk1 = if bit == 1 {
        pk.clone()
    } else {
        RsaPublicKey::new(pk.n() + BigUint::new(vec![2]), pk.e().clone()).unwrap()
    };

    ((pk0, pk1), sk)
}

pub fn alice_ot1(bob_keys: [RsaPublicKey; 2], msg0: &[u8], msg1: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // ensure bob_keys are correctly related...
    assert_eq!(
        bob_keys[0].n() + BigUint::new(vec![2]),
        bob_keys[1].n().clone(),
        "Bob keys are not correctly related!"
    );

    let mut rng = thread_rng();
    // encrypt each message to the corresponding public key
    let ct0 = bob_keys[0]
        .encrypt(&mut rng, Pkcs1v15Encrypt, msg0)
        .unwrap();
    let ct1 = bob_keys[1]
        .encrypt(&mut rng, Pkcs1v15Encrypt, msg1)
        .unwrap();

    (ct0, ct1)
}

pub fn bob_ot2(bit: usize, bob_sk: RsaPrivateKey, alice_ctxts: [Vec<u8>; 2]) -> Vec<u8> {
    // decrypt the correct ciphertext
    let ct = &alice_ctxts[bit];
    bob_sk.decrypt(Pkcs1v15Encrypt, ct).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ot() {
        let msg0 = b"zero message";
        let msg1 = b"one message";
        for bit in 0..1 {
            let ((b0, b1), sk) = bob_ot1(bit);
            let (ct0, ct1) = alice_ot1([b0, b1], msg0, msg1);
            let msg = bob_ot2(bit, sk, [ct0, ct1]);
            if bit == 0 {
                assert_eq!(msg, msg0);
            } else {
                assert_eq!(msg, msg1);
            }
        }
    }
}
