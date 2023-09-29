use blst::min_pk as blst_impl;
use rand::Rng;

// Example attack codes from https://eprint.iacr.org/2021/323.pdf
// and https://eprint.iacr.org/2021/377.pdf

// Summary
// 1. Validate keys, and signatures - check for 0
// 2. Use fast_aggregate_verify() instead of aggregate_verify()

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[test]
fn test_zero_pk_sig() {
    // Checks that zero public key and signatures are invalid.

    let pk_bytes = [0u8; 48];
    let sig_bytes = [0u8; 96];

    assert!(matches!(
        blst_impl::PublicKey::from_bytes(&pk_bytes),
        Err(blst::BLST_ERROR::BLST_BAD_ENCODING)
    ));

    assert!(matches!(
        blst_impl::Signature::from_bytes(&sig_bytes),
        Err(blst::BLST_ERROR::BLST_BAD_ENCODING)
    ));
}

#[test]
fn test_splitting_zero_attack() {
    let sk3_bytes = [
        0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5,
        6, 7,
    ];
    let sk3 = blst_impl::SecretKey::deserialize(&sk3_bytes).unwrap();
    let pk3 = sk3.sk_to_pk();
    let m3: &[u8] = b"user message";
    let sig3 = sk3.sign(m3, DST, &[]);

    // Here, we have sk1 + sk2 = 0, and they're valid public keys.
    let sk1_bytes = [
        99, 64, 58, 175, 15, 139, 113, 184, 37, 222, 127, 204, 233, 209, 34, 8, 61, 27, 85, 251,
        68, 31, 255, 214, 8, 189, 190, 71, 198, 16, 210, 91,
    ];
    let sk2_bytes = [
        16, 173, 108, 164, 26, 18, 11, 144, 13, 91, 88, 59, 31, 208, 181, 253, 22, 162, 78, 7, 187,
        222, 92, 40, 247, 66, 65, 183, 57, 239, 45, 166,
    ];

    let sk1 = blst_impl::SecretKey::deserialize(&sk1_bytes).unwrap();
    let sk2 = blst_impl::SecretKey::deserialize(&sk2_bytes).unwrap();

    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();
    let m = b"arbitrary message";

    // The attacker claims that sig3 is an aggregate signature of (m, m3, m) signed by
    // (sk1, sk2, sk3) respecively.
    let agg_sig = blst_impl::AggregateSignature::aggregate(&[&sig3], true).unwrap();

    let result =
        agg_sig
            .to_signature()
            .aggregate_verify(true, &[m, m3, m], DST, &[&pk1, &pk3, &pk2], true);
    println!("AggregateVerify of (m , m3, m): {:?}", result);

    assert_eq!(result, blst::BLST_ERROR::BLST_SUCCESS);
}

#[test]
fn test_consensus_attack() {
    // sk1 + sk2 = 0.
    let sk1_bytes = [
        99, 64, 58, 175, 15, 139, 113, 184, 37, 222, 127, 204, 233, 209, 34, 8, 61, 27, 85, 251,
        68, 31, 255, 214, 8, 189, 190, 71, 198, 16, 210, 91,
    ];
    let sk2_bytes = [
        16, 173, 108, 164, 26, 18, 11, 144, 13, 91, 88, 59, 31, 208, 181, 253, 22, 162, 78, 7, 187,
        222, 92, 40, 247, 66, 65, 183, 57, 239, 45, 166,
    ];

    let sk1 = blst_impl::SecretKey::deserialize(&sk1_bytes).unwrap();
    let sk2 = blst_impl::SecretKey::deserialize(&sk2_bytes).unwrap();

    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();

    let msg = b"message";
    let sig1 = sk1.sign(msg, DST, &[]);
    let sig2 = sk2.sign(msg, DST, &[]);
    let agg_sig = blst_impl::AggregateSignature::aggregate(&[&sig1, &sig2], true).unwrap();

    let fast_aggregate_verify_result =
        agg_sig
            .to_signature()
            .fast_aggregate_verify(true, msg, DST, &[&pk1, &pk2])
            == blst::BLST_ERROR::BLST_SUCCESS;

    let aggregate_verify_result =
        agg_sig
            .to_signature()
            .aggregate_verify(true, &[msg, msg], DST, &[&pk1, &pk2], true)
            == blst::BLST_ERROR::BLST_SUCCESS;
    println!("FastAggregateVerify: {}", fast_aggregate_verify_result);
    println!("AggregateVerify: {}", aggregate_verify_result);

    // Both should return false.
    assert!(!fast_aggregate_verify_result);
    // but aggrgate_verify_result returns true
    assert_ne!(fast_aggregate_verify_result, aggregate_verify_result);
}

#[test]
fn test_consensus_attack2() {
    let mut rng = rand::thread_rng();
    let sk0_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();
    let sk1_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();
    let sk2_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();
    let sk3_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();
    let sk4_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();

    let sk0 = blst_impl::SecretKey::key_gen(&sk0_bytes, &[]).unwrap();
    let sk1 = blst_impl::SecretKey::key_gen(&sk1_bytes, &[]).unwrap();
    let sk2 = blst_impl::SecretKey::key_gen(&sk2_bytes, &[]).unwrap();
    let sk3 = blst_impl::SecretKey::key_gen(&sk3_bytes, &[]).unwrap();
    let sk4 = blst_impl::SecretKey::key_gen(&sk4_bytes, &[]).unwrap();

    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();
    let pk3 = sk3.sk_to_pk();
    let pk4 = sk4.sk_to_pk();

    let msg = b"message";
    let sig0 = sk0.sign(msg, DST, &[]);
    let mut p: blst::blst_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut p, &sig0.point);
    }

    println!("Consensus attack against proof of possession");
    let msg1 = b"message0";
    let msg2 = b"message0";
    let msg3 = b"message1";
    let msg4 = b"message1";

    let sig1 = sk1.sign(msg1, DST, &[]);
    let sig2 = sk2.sign(msg2, DST, &[]);
    let sig3 = sk3.sign(msg3, DST, &[]);
    let sig4 = sk4.sign(msg4, DST, &[]);

    // compute -2 * p
    let mut temp = <blst::blst_p2>::default();
    let scalar_two: u8 = 2;
    unsafe {
        blst::blst_p2_mult(&mut temp, &p, &scalar_two, 8);
        blst::blst_p2_cneg(&mut temp, true /* not sure what this is*/);
    }

    // sig1 - 2p
    let mut sig1_prime_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut sig1_prime_p2, &sig1.point);
        blst::blst_p2_add(&mut sig1_prime_p2, &sig1_prime_p2, &temp);
    }

    // sig2 + p
    let mut sig2_prime_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut sig2_prime_p2, &sig2.point);
        blst::blst_p2_add(&mut sig2_prime_p2, &sig2_prime_p2, &p);
    }

    // - p
    let mut neg_p = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut neg_p, &sig0.point);
        blst::blst_p2_cneg(&mut neg_p, true /* not sure what this is*/);
    }

    // sig3 - p
    let mut sig3_prime_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut sig3_prime_p2, &sig3.point);
        blst::blst_p2_add(&mut sig3_prime_p2, &sig3_prime_p2, &neg_p);
    }

    // sig4 + 2p
    let mut two_p = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_mult(&mut two_p, &p, &scalar_two, 8);
    }

    let mut sig4_prime_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut sig4_prime_p2, &sig4.point);
        blst::blst_p2_add(&mut sig4_prime_p2, &sig4_prime_p2, &two_p);
    }

    let mut sig1_prime_p2_affine = <blst::blst_p2_affine>::default();
    unsafe {
        blst::blst_p2_to_affine(&mut sig1_prime_p2_affine, &sig1_prime_p2);
    }
    let sig1_prime = blst_impl::Signature {
        point: sig1_prime_p2_affine,
    };
    let mut sig2_prime_p2_affine = <blst::blst_p2_affine>::default();
    unsafe {
        blst::blst_p2_to_affine(&mut sig2_prime_p2_affine, &sig2_prime_p2);
    }
    let sig2_prime = blst_impl::Signature {
        point: sig2_prime_p2_affine,
    };
    let mut sig3_prime_p2_affine = <blst::blst_p2_affine>::default();
    unsafe {
        blst::blst_p2_to_affine(&mut sig3_prime_p2_affine, &sig3_prime_p2);
    }
    let sig3_prime = blst_impl::Signature {
        point: sig3_prime_p2_affine,
    };
    let mut sig4_prime_p2_affine = <blst::blst_p2_affine>::default();
    unsafe {
        blst::blst_p2_to_affine(&mut sig4_prime_p2_affine, &sig4_prime_p2);
    }
    let sig4_prime = blst_impl::Signature {
        point: sig4_prime_p2_affine,
    };

    println!("subgroup check sig1_prime: {}", sig1_prime.subgroup_check());
    println!("subgroup check sig2_prime: {}", sig2_prime.subgroup_check());
    println!("subgroup check sig3_prime: {}", sig3_prime.subgroup_check());
    println!("subgroup check sig4_prime: {}", sig4_prime.subgroup_check());

    assert!(sig1_prime.validate(true).is_ok());
    assert!(sig2_prime.validate(true).is_ok());
    assert!(sig3_prime.validate(true).is_ok());
    assert!(sig4_prime.validate(true).is_ok());

    let sig1234_prime = blst_impl::AggregateSignature::aggregate(
        &[&sig1_prime, &sig2_prime, &sig3_prime, &sig4_prime],
        true,
    )
    .unwrap();

    println!(
        "User1 aggregate verify 4 messages: {}",
        sig1234_prime.to_signature().aggregate_verify(
            true,
            &[msg1, msg2, msg3, msg4],
            DST,
            &[&pk1, &pk2, &pk3, &pk4],
            true
        ) == blst::BLST_ERROR::BLST_SUCCESS
    );

    let sig12_prime =
        blst_impl::AggregateSignature::aggregate(&[&sig1_prime, &sig2_prime], true).unwrap();
    let sig34_prime =
        blst_impl::AggregateSignature::aggregate(&[&sig3_prime, &sig4_prime], true).unwrap();

    assert!(sig12_prime.validate().is_ok());
    assert!(sig34_prime.validate().is_ok());

    let pk12 = blst_impl::AggregatePublicKey::aggregate(&[&pk1, &pk2], true).unwrap();
    let pk34 = blst_impl::AggregatePublicKey::aggregate(&[&pk3, &pk4], true).unwrap();
    println!(
        "User2 fast aggregate verify the first 2 messages and the last 2 messages.\
        They all return false so user2 discards sig12_prime and sig34_prime: {} {}",
        sig12_prime
            .to_signature()
            .fast_aggregate_verify(true, msg1, DST, &[&pk1, &pk2])
            == blst::BLST_ERROR::BLST_SUCCESS,
        sig34_prime
            .to_signature()
            .fast_aggregate_verify(true, msg3, DST, &[&pk3, &pk4])
            == blst::BLST_ERROR::BLST_SUCCESS
    );

    let sig12_sig34_aggregate_verify = blst_impl::AggregateSignature::aggregate(
        &[&sig12_prime.to_signature(), &sig34_prime.to_signature()],
        true,
    )
    .unwrap()
    .to_signature()
    .aggregate_verify(
        true,
        &[msg1, msg3],
        DST,
        &[&pk12.to_public_key(), &pk34.to_public_key()],
        true,
    );

    println!(
        "User2 never executes this last step because sig12_prime and sig34_prime are invalid, {}",
        sig12_sig34_aggregate_verify == blst::BLST_ERROR::BLST_SUCCESS
    );

    // Left: aggregate_verify() of 4 messages.
    let left = sig1234_prime.to_signature().aggregate_verify(
        true,
        &[msg1, msg2, msg3, msg4],
        DST,
        &[&pk1, &pk2, &pk3, &pk4],
        true,
    ) == blst::BLST_ERROR::BLST_SUCCESS;

    // Right: fast_aggregate_verify() of 2 messages.
    let right = sig12_prime
        .to_signature()
        .fast_aggregate_verify(true, msg, DST, &[&pk1, &pk2])
        == blst::BLST_ERROR::BLST_SUCCESS
        && sig34_prime
            .to_signature()
            .fast_aggregate_verify(true, msg, DST, &[&pk3, &pk4])
            == blst::BLST_ERROR::BLST_SUCCESS
        && sig12_sig34_aggregate_verify == blst::BLST_ERROR::BLST_SUCCESS;

    println!(
        "Mathematically we expect both sides return the same result, but they do not {}, {}",
        left, right
    );

    assert!(left);
    assert_ne!(left, right);
}

#[test]
fn test_consensus_attack3() {
    let mut rng = rand::thread_rng();
    let sk0_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();
    let sk1_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();
    let sk2_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();
    let sk3_bytes = (0..48).map(|_| rng.gen()).collect::<Vec<_>>();

    let sk0 = blst_impl::SecretKey::key_gen(&sk0_bytes, &[]).unwrap();
    let sk1 = blst_impl::SecretKey::key_gen(&sk1_bytes, &[]).unwrap();
    let sk2 = blst_impl::SecretKey::key_gen(&sk2_bytes, &[]).unwrap();
    let sk3 = blst_impl::SecretKey::key_gen(&sk3_bytes, &[]).unwrap();

    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();
    let pk3 = sk3.sk_to_pk();

    let msg = b"message";

    let sig0 = sk0.sign(msg, DST, &[]);
    let sig1 = sk1.sign(msg, DST, &[]);
    let sig2 = sk2.sign(msg, DST, &[]);
    let sig3 = sk3.sign(msg, DST, &[]);

    let mut p: blst::blst_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut p, &sig0.point);
    }

    // compute -2p
    let mut temp = <blst::blst_p2>::default();
    let scalar_two: u8 = 2;
    unsafe {
        blst::blst_p2_mult(&mut temp, &p, &scalar_two, 8);
        blst::blst_p2_cneg(&mut temp, true /* not sure what this is*/);
    }

    // sig1 - 2p
    let mut sig1_prime_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut sig1_prime_p2, &sig1.point);
        blst::blst_p2_add(&mut sig1_prime_p2, &sig1_prime_p2, &temp);
    }

    // sig2 - p
    let mut temp2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut temp2, &sig0.point);
        blst::blst_p2_cneg(&mut temp2, true);
    }
    let mut sig2_prime_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut sig2_prime_p2, &sig2.point);
        blst::blst_p2_add(&mut sig2_prime_p2, &sig2_prime_p2, &temp2);
    }

    // sig3 + 3p
    let mut temp3 = <blst::blst_p2>::default();
    let scalar_three: u8 = 3;
    unsafe {
        blst::blst_p2_mult(&mut temp3, &p, &scalar_three, 8);
    }
    let mut sig3_prime_p2 = <blst::blst_p2>::default();
    unsafe {
        blst::blst_p2_from_affine(&mut sig3_prime_p2, &sig3.point);
        blst::blst_p2_add(&mut sig3_prime_p2, &sig3_prime_p2, &temp3);
    }

    let mut sig1_prime_p2_affine = <blst::blst_p2_affine>::default();
    unsafe {
        blst::blst_p2_to_affine(&mut sig1_prime_p2_affine, &sig1_prime_p2);
    }
    let sig1_prime = blst_impl::Signature {
        point: sig1_prime_p2_affine,
    };
    let mut sig2_prime_p2_affine = <blst::blst_p2_affine>::default();
    unsafe {
        blst::blst_p2_to_affine(&mut sig2_prime_p2_affine, &sig2_prime_p2);
    }
    let sig2_prime = blst_impl::Signature {
        point: sig2_prime_p2_affine,
    };
    let mut sig3_prime_p2_affine = <blst::blst_p2_affine>::default();
    unsafe {
        blst::blst_p2_to_affine(&mut sig3_prime_p2_affine, &sig3_prime_p2);
    }
    let sig3_prime = blst_impl::Signature {
        point: sig3_prime_p2_affine,
    };

    println!("subgroup check sig1_prime: {}", sig1_prime.subgroup_check());
    println!("subgroup check sig2_prime: {}", sig2_prime.subgroup_check());
    println!("subgroup check sig3_prime: {}", sig3_prime.subgroup_check());

    assert!(sig1_prime.validate(true).is_ok());
    assert!(sig2_prime.validate(true).is_ok());
    assert!(sig3_prime.validate(true).is_ok());

    let sig123_prime =
        blst_impl::AggregateSignature::aggregate(&[&sig1_prime, &sig2_prime, &sig3_prime], true)
            .unwrap();
    let sig12_prime =
        blst_impl::AggregateSignature::aggregate(&[&sig1_prime, &sig2_prime], true).unwrap();

    let sig123_prime_result =
        sig123_prime
            .to_signature()
            .fast_aggregate_verify(true, msg, DST, &[&pk1, &pk2, &pk3]);

    let sig12_prime_result =
        sig12_prime
            .to_signature()
            .fast_aggregate_verify(true, msg, DST, &[&pk1, &pk2]);

    let sig12_3_prime =
        blst_impl::AggregateSignature::aggregate(&[&sig12_prime.to_signature(), &sig3_prime], true)
            .unwrap();

    let pk12 = blst_impl::AggregatePublicKey::aggregate(&[&pk1, &pk2], true)
        .unwrap()
        .to_public_key();
    let sig12_3_prime_result =
        sig12_3_prime
            .to_signature()
            .fast_aggregate_verify(true, msg, DST, &[&pk12, &pk3]);

    println!("sig123_prime_result: {:?}", sig123_prime_result);
    println!("sig12_prime_result: {:?}", sig12_prime_result);
    println!("sig12_3_prime_result: {:?}", sig12_3_prime_result);

    assert_eq!(sig123_prime_result, blst::BLST_ERROR::BLST_SUCCESS);
    assert_ne!(sig123_prime_result, sig12_prime_result);
    assert_eq!(sig12_3_prime_result, blst::BLST_ERROR::BLST_SUCCESS);
}
