use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Nonce, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::io::{read_message, wait_for_message, wait_for_read, write_message};
use crate::ot::{OTReceiver, OTSender};

mod io;
mod ops;
mod ot;

// A party in the computation
#[derive(Copy, Clone)]
enum Party {
    GARBLER,
    EVALUATOR,
}

// The external wire representation.
// This is an index into the circuit's `wires` array
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct Wire(usize);

// A wire in the circuit
// It is either an input wire,
// or the output of a gate
#[derive(Copy, Clone)]
enum InnerWire {
    Input(usize),
    Intermeidate(usize),
}

// A gate in the circuit
struct Gate {
    // The function that implements the gate
    // This should only operate on booleans
    op: fn(usize, usize) -> usize,

    // Left input wire
    left: Wire,
    // right input wire
    right: Wire,
    // output wire,
    output: Wire,
}

impl Gate {
    fn new(op: fn(usize, usize) -> usize, left: Wire, right: Wire, output: Wire) -> Self {
        Self {
            op,
            left,
            right,
            output,
        }
    }
}

/// Represents the circuit we want to garble
pub struct Circuit {
    // Represents the input to the circuit
    // Each input belongs to a party
    inputs: Vec<(Party, Wire)>,

    // An output wire
    outputs: Vec<Wire>,

    // The gates used in the circuit
    gates: Vec<Gate>,

    // Wires in the circuit
    wires: Vec<InnerWire>,
}

impl Circuit {
    fn new() -> Self {
        Self {
            inputs: vec![],
            outputs: vec![],
            gates: vec![],
            wires: vec![],
        }
    }

    /// Add an input to the circuit, which belongs to `party`
    fn add_input(&mut self, party: Party) -> Wire {
        let wire = Wire(self.wires.len());
        let inner_wire = InnerWire::Input(self.inputs.len());
        self.inputs.push((party, wire));
        self.wires.push(inner_wire.clone());
        wire
    }

    /// Mark a wire as an output
    fn add_output(&mut self, wire: Wire) {
        self.outputs.push(wire);
    }

    /// Add a gate to the circuit
    /// `op` should be a function which implements the gate
    fn add_gate(&mut self, op: fn(usize, usize) -> usize, left: Wire, right: Wire) -> Wire {
        let wire = InnerWire::Intermeidate(self.gates.len());
        self.wires.push(wire.clone());
        let output_wire = Wire(self.wires.len() - 1);
        self.gates.push(Gate::new(op, left, right, output_wire));
        output_wire
    }

    // Evaluate the circuit in the clear
    // For testing only
    fn evaluate(&self, inputs: Vec<usize>) -> Vec<usize> {
        let mut gate_outputs: Vec<usize> = vec![];

        let get_wire_value = |wire: &Wire, gate_outputs: &[usize]| {
            let inner_wire = &self.wires[wire.0];
            match inner_wire {
                InnerWire::Input(index) => inputs[*index],
                InnerWire::Intermeidate(index) => gate_outputs[*index],
            }
        };

        for gate in &self.gates {
            let left_input = get_wire_value(&gate.left, &gate_outputs);
            let right_input = get_wire_value(&gate.right, &gate_outputs);
            let output = (gate.op)(left_input, right_input);
            gate_outputs.push(output);
        }

        let mut result = vec![];
        for output in &self.outputs {
            result.push(get_wire_value(&output, &gate_outputs));
        }
        result
    }

    pub fn garble(&self) -> GarbledCircuit {
        // Create a key pair for each wire in the circuit
        let wire_keys = self
            .wires
            .iter()
            .map(|_| {
                [
                    Aes256Gcm::generate_key(OsRng),
                    Aes256Gcm::generate_key(OsRng),
                ]
            })
            .collect::<Vec<_>>();

        // garble each gate
        let mut garbled_gates = vec![];
        for gate in &self.gates {
            // get the keys for each wire to the gate
            let left_keys = &wire_keys[gate.left.0];
            let right_keys = &wire_keys[gate.right.0];
            let output_keys = &wire_keys[gate.output.0];

            // create the garbled gate
            let garble_table = garble(left_keys, right_keys, output_keys, gate);
            let garbled_gate = GarbledGate::new(garble_table, gate.left, gate.right, gate.output);

            garbled_gates.push(garbled_gate);
        }

        GarbledCircuit {
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            gates: garbled_gates,
            wires: self.wires.clone(),
            wire_keys,
        }
    }
}

/// A garbled gate
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct GarbledGate {
    // The map from input keys to output keys
    #[serde_as(as = "Vec<(_, _)>")]
    map: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>,

    // Left input wire
    left: Wire,
    // right input wire
    right: Wire,
    // output wire,
    output: Wire,
}

impl GarbledGate {
    fn new(
        map: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>,
        left: Wire,
        right: Wire,
        output: Wire,
    ) -> Self {
        Self {
            map,
            left,
            right,
            output,
        }
    }
}

/// A garbled circuit
/// Mirrors the Circuit struct, except the gates are GarbledGates
pub struct GarbledCircuit {
    // Represents the input to the circuit
    // Each input belongs to a party
    inputs: Vec<(Party, Wire)>,
    outputs: Vec<Wire>,

    // The gates used in the circuit
    gates: Vec<GarbledGate>,

    // Wires in the circuit
    wires: Vec<InnerWire>,
    wire_keys: Vec<[Key<Aes256Gcm>; 2]>,
}

impl GarbledCircuit {
    pub fn garbler(&self, input_values: Vec<usize>) -> Vec<usize> {
        let mut count = 0;
        for (i, (input, wire)) in self.inputs.iter().enumerate() {
            // send over keys for alice's inputs
            if matches!(input, Party::GARBLER) {
                let key = if input_values[count] == 0 {
                    self.wire_keys[wire.0][0]
                } else {
                    self.wire_keys[wire.0][1]
                };
                write_message(&key[..], &format!("input {}", i));
                wait_for_read(&format!("input {}", i));

                count += 1;
            } else {
                // OT the key for bobs input
                OTSender::send(&self.wire_keys[wire.0][0], &self.wire_keys[wire.0][1]);
            }
        }

        // Send bob the garbled gates
        let serialized_gates = serde_json::to_string(&self.gates).unwrap();
        write_message(serialized_gates.as_bytes(), "gates");
        wait_for_read(&format!("gates"));

        // receive output back
        let mut output_values = vec![];
        for (i, output) in self.outputs.iter().enumerate() {
            wait_for_message(&format!("output {}", i));
            let output_key = read_message();

            if output_key == self.wire_keys[output.0][0][..] {
                output_values.push(0);
            } else if output_key == &self.wire_keys[output.0][1][..] {
                output_values.push(1);
            } else {
                panic!("Unexpected output key!");
            }
        }

        return output_values;
    }

    /// Run by the evaluator
    /// This doesn't need to know the garbled circuit, since Alice sends
    /// it anyway
    /// However, we expect that Bob knows the circuit topology
    pub fn evaluator(circuit: &Circuit, input_values: Vec<usize>) {
        let mut count = 0;
        let mut wire_keys: Vec<Option<Key<Aes256Gcm>>> = vec![None; circuit.wires.len()];

        for (i, (input, wire)) in circuit.inputs.iter().enumerate() {
            if matches!(input, Party::GARBLER) {
                // get key for alice's inputs
                wait_for_message(&format!("input {}", i));
                let key = read_message();
                wire_keys[wire.0] = Some(Key::<Aes256Gcm>::from_slice(&key).clone());
            } else {
                // OT the key for bobs input
                let bit = input_values[count];
                let key = OTReceiver::receive(bit);
                wire_keys[wire.0] = Some(Key::<Aes256Gcm>::from_slice(&key).clone());

                count += 1;
            }
        }

        // get the garbled gates from Alice
        wait_for_message("gates");
        let serialized_gates = read_message();
        let gates: Vec<GarbledGate> =
            serde_json::from_str(&String::from_utf8(serialized_gates).unwrap()).unwrap();

        // evaluate all the garbled gates
        for (i, gate) in gates.iter().enumerate() {
            let left_key = wire_keys[gate.left.0].unwrap();
            let right_key = wire_keys[gate.right.0].unwrap();

            let output_key = evaluate(&gate.map, &left_key, &right_key);
            wire_keys[gate.output.0] = Some(output_key);
        }

        // send output back
        for (i, output) in circuit.outputs.iter().enumerate() {
            write_message(&wire_keys[output.0].unwrap(), &format!("output {}", i));
        }
    }
}

/// Constructs a new millionaires circuit (e.g. a >= b)
/// for some bit-width n
///
/// The circuit performs:
///
/// (a_0 > b_0) | ((a_0 == b_0) & (a_1 > b_1)
///             | ...
///             | ((a_0 == b_0) & ... & (a_n-2 == b_n-2) & (a_n-1 >= b_n-1)
///
/// where a_i is the ith bit of a
pub fn new_millionaires_circuit(n: u32) -> Circuit {
    use crate::ops::*;
    let n = n as usize;

    let mut circuit = Circuit::new();

    // add alice and bobs inputs
    let mut alices = vec![];
    let mut bobs = vec![];
    for _ in 0..n {
        alices.push(circuit.add_input(Party::GARBLER));
    }
    for _ in 0..n {
        bobs.push(circuit.add_input(Party::EVALUATOR));
    }

    // create terms (a_i == b_i) and (a_i > b_i) for each bit
    let mut gts = vec![];
    let mut eqs = vec![];
    for i in 0..n {
        gts.push(circuit.add_gate(a_gt_b, alices[i], bobs[i]));
        eqs.push(circuit.add_gate(a_eq_b, alices[i], bobs[i]));
    }

    // create terms (a_0 == b_0) & ... & (a_i-1 == b_i-1) & (a_i > b_i)
    let mut ands = vec![];
    for i in 1..n {
        let mut and = if i < n - 1 {
            circuit.add_gate(a_gt_b, alices[i], bobs[i])
        } else {
            circuit.add_gate(a_geq_b, alices[i], bobs[i])
        };
        for j in 0..i {
            and = circuit.add_gate(a_and_b, and, eqs[j]);
        }
        ands.push(and);
    }

    // or all the ands together
    let mut ors = circuit.add_gate(a_gt_b, alices[0], bobs[0]);
    for i in 1..n {
        ors = circuit.add_gate(a_or_b, ors, ands[i - 1]);
    }

    circuit.add_output(ors);
    circuit
}

/// garbles a gate
fn garble(
    left_keys: &[Key<Aes256Gcm>; 2],
    right_keys: &[Key<Aes256Gcm>; 2],
    out_keys: &[Key<Aes256Gcm>; 2],
    gate: &Gate,
) -> HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)> {
    // construct the Garbled Gate table
    let mut result = HashMap::new();
    let inputs = vec![(0, 0), (0, 1), (1, 0), (1, 1)];

    for (left, right) in &inputs {
        // get the keys for the inputs
        let left_key = left_keys[*left];
        let right_key = right_keys[*right];
        let out_key = out_keys[(gate.op)(*left, *right)];

        // hash the corresponding keys
        let mut hasher = Sha256::new();
        hasher.update(left_key);
        hasher.update(right_key);
        let hash = hasher.finalize();

        // encrypt the output key
        // NOTE: I use xor to combine the keys (instead of concatination as in `easy.pdf`)
        //       This is secure.
        //       Assume bob gets keys K_a and K_b, and doesn't see keys K_a' K_b'
        //       Then the encryption key for each table except the correct one is:
        //       (K_a' ^ K_b)
        //       (K_a ^ K_b')
        //       (K_a' & K_b')
        //       Because K_a' and K_b' are uniformly random, each of the above
        //       encryption keys are also uniformly random in Bob's view.
        //       Therefore, he cannot guess the keys, so he cannot decrypt those rows.
        let key = left_key
            .iter()
            .zip(right_key)
            .map(|(k1, k2)| k1 ^ k2)
            .collect::<Key<Aes256Gcm>>();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, &*out_key).unwrap();
        result.insert(hash[..].to_vec(), (ciphertext.into(), nonce.to_vec()));
    }

    result
}

/// evaulate a garbled gate
fn evaluate(
    garbled_gate: &HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>,
    left_key: &Key<Aes256Gcm>,
    right_key: &Key<Aes256Gcm>,
) -> Key<Aes256Gcm> {
    let mut hasher = Sha256::new();
    hasher.update(left_key);
    hasher.update(right_key);
    let hash = hasher.finalize();

    // compute the encryption key
    let key = left_key
        .iter()
        .zip(right_key)
        .map(|(k1, k2)| k1 ^ k2)
        .collect::<Key<Aes256Gcm>>();

    // decrypt the output key
    let (ciphertext, nonce) = garbled_gate.get(&hash[..].to_vec()).unwrap();
    let cipher = Aes256Gcm::new(&key);
    let out_key = cipher
        .decrypt(Nonce::<Aes256Gcm>::from_slice(nonce), ciphertext.as_ref())
        .unwrap();
    Key::<Aes256Gcm>::from_iter(out_key.into_iter())
}

/// Helper function that decomposes a value into n bits
pub fn decompose(value: usize, n: u32) -> Vec<usize> {
    let mut result = vec![];
    for i in 0..n {
        let mask = 1 << (n - i - 1);
        let bit = (value & mask) >> (n - i - 1);
        result.push(bit);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test a garbled gate evaluation
    #[test]
    fn garble_evaluates_correctly() {
        let gate = Gate::new(ops::a_gt_b, Wire(0), Wire(0), Wire(0));

        let keys = (0..6)
            .map(|_| Aes256Gcm::generate_key(OsRng))
            .collect::<Vec<_>>();

        let garbled_gate = garble(
            &[keys[0], keys[1]],
            &[keys[2], keys[3]],
            &[keys[4], keys[5]],
            &gate,
        );
        let out_key = evaluate(&garbled_gate, &keys[0], &keys[3]);
        assert_eq!(out_key, keys[4]);
    }

    fn check_million_circuit_for_n(n: u32) {
        let millionaires = new_millionaires_circuit(n);

        for a in 0..2usize.pow(n) {
            for b in 0..2usize.pow(n) {
                let mut inputs = vec![];
                inputs.extend(decompose(a, n));
                inputs.extend(decompose(b, n));

                assert_eq!(
                    millionaires.evaluate(inputs.clone()),
                    vec![(a >= b) as usize],
                    "{} {}",
                    a,
                    b
                );
            }
        }
    }

    /// Test that the millionaires is correct
    #[test]
    fn millionaires_circuit_evaluates_correctly() {
        check_million_circuit_for_n(2);
        check_million_circuit_for_n(3);
        check_million_circuit_for_n(4);
    }
}
