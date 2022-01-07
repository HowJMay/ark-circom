use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine, G1Projective, G2Projective};
use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use ark_ff::{BigInteger256, FromBytes, PrimeField};
use num::FromPrimitive;
use num_bigint::BigUint;
use std::fs::File;

#[test]
fn groth16_proof() -> Result<()> {
    let inputs = _parse_public_inputs_bn254_json_d();
    let json = std::fs::read_to_string("./test-vectors/circom/verification_key.json").unwrap();
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    let vk= ark_groth16::VerifyingKey::<Bn254> {
        alpha_g1: json_to_g1(&json, "vk_alpha_1"),
        beta_g2: json_to_g2(&json, "vk_beta_2"),
        gamma_g2: json_to_g2(&json, "vk_gamma_2"),
        delta_g2: json_to_g2(&json, "vk_delta_2"),
        gamma_abc_g1: json_to_g1_vec(&json, "IC"),
    };
    
    let json = ark_std::fs::read_to_string("./test-vectors/circom/proof.json").unwrap();
	let json: serde_json::Value = serde_json::from_str(&json).unwrap();
	let proof = _parse_proof_bn254_json(&json);
    let pvk = prepare_verifying_key(&vk);

    let verified = verify_proof(&pvk, &proof, &inputs)?;

    assert_eq!(verified, true);

    Ok(())
}


pub fn _parse_proof_bn254_json(json: &serde_json::Value) -> ark_groth16::Proof<Bn254> {
	let pi_a = json_to_g1(json, "pi_a");
	let pi_b = json_to_g2(json, "pi_b");
	let pi_c = json_to_g1(json, "pi_c");

	ark_groth16::Proof {
		a: pi_a,
		b: pi_b,
		c: pi_c,
	}
}


fn _parse_public_inputs_bn254_json(json: &serde_json::Value) -> Vec<Fr> {
	let a = json_to_fr(json, "a");
    let b = json_to_fr(json, "b");
	
	let mut public_inputs = vec![a,b];
    println!("public_inputs[0] = {}\n",public_inputs[0]);
    println!("public_inputs[1] = {}\n",public_inputs[1]);
	public_inputs
}

fn _parse_public_inputs_bn254_json_d() -> Vec<Fr> {
	let a = fr_from_int(33);
	
	let mut public_inputs = vec![a];
	public_inputs
}

fn json_to_g1(json: &serde_json::Value, key: &str) -> G1Affine {
    let els: Vec<String> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_str().unwrap().to_string())
        .collect();
    G1Affine::from(G1Projective::new(
        fq_from_str(&els[0]),
        fq_from_str(&els[1]),
        fq_from_str(&els[2]),
    ))
}

fn json_to_g1_vec(json: &serde_json::Value, key: &str) -> Vec<G1Affine> {
    let els: Vec<Vec<String>> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect::<Vec<String>>()
        })
        .collect();

    els.iter()
        .map(|coords| {
            G1Affine::from(G1Projective::new(
                fq_from_str(&coords[0]),
                fq_from_str(&coords[1]),
                fq_from_str(&coords[2]),
            ))
        })
        .collect()
}

fn json_to_g2(json: &serde_json::Value, key: &str) -> G2Affine {
    let els: Vec<Vec<String>> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect::<Vec<String>>()
        })
        .collect();

    let x = Fq2::new(fq_from_str(&els[0][0]), fq_from_str(&els[0][1]));
    let y = Fq2::new(fq_from_str(&els[1][0]), fq_from_str(&els[1][1]));
    let z = Fq2::new(fq_from_str(&els[2][0]), fq_from_str(&els[2][1]));
    G2Affine::from(G2Projective::new(x, y, z))
}

use std::str::FromStr;
use std::convert::TryFrom;

fn fq_from_str(s: &str) -> Fq {
    BigInteger256::try_from(BigUint::from_str(s).unwrap())
        .unwrap()
        .into()
}

fn json_to_fr(json: &serde_json::Value, key: &str) -> Fr {	
    let els = json.get(key).unwrap();

	fr_from_int(els.as_i64().unwrap())
}

fn fr_from_int(n: i64) -> Fr {
	BigInteger256::try_from(BigUint::from_i64(n).unwrap())
		.unwrap()
		.into()
}

fn fr_from_str(s: &str) -> Fr {
	BigInteger256::try_from(BigUint::from_str(s).unwrap())
		.unwrap()
		.into()
}


#[test]
fn groth16_proof_wrong_input() {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    // This isn't a public input to the circuit, should faild
    builder.push_input("foo", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let _params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

    builder.build().unwrap_err();
}

#[test]
#[cfg(feature = "circom-2")]
fn groth16_proof_circom2() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/circom2_multiplier2.wasm",
        "./test-vectors/circom2_multiplier2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    let proof = prove(circom, &params, &mut rng)?;

    let pvk = prepare_verifying_key(&params.vk);

    let verified = verify_proof(&pvk, &proof, &inputs)?;

    assert!(verified);

    Ok(())
}
