use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Nonce, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};
use std::collections::HashMap;

mod ops;

// A party in the computation
// We are doing 2PC, so this should
// always be either 0 or 1
#[derive(Copy, Clone)]
struct Party(usize);

// TODO: is there a better wire/gate representation?
#[derive(Copy, Clone)]
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

struct Circuit {
    // Represents the input to the circuit
    // Each input belongs to a party
    inputs: Vec<Party>,
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

    fn add_input(&mut self, party: Party) -> Wire {
        self.inputs.push(party);
        let wire = InnerWire::Input(self.inputs.len() - 1);
        self.wires.push(wire.clone());
        Wire(self.wires.len() - 1)
    }

    fn add_output(&mut self, wire: Wire) {
        self.outputs.push(wire);
    }

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

    fn garble(&self) -> GarbledCircuit {
        // each wire gets two keys
        // TODO: refactor into cleaner key-pair struct
        let wire_keys = self
            .wires
            .iter()
            .map(|wire| {
                [
                    Aes256Gcm::generate_key(OsRng),
                    Aes256Gcm::generate_key(OsRng),
                ]
            })
            .collect::<Vec<_>>();

        let mut garbled_gates = vec![];
        for gate in &self.gates {
            let left_wires = &wire_keys[gate.left.0];
            let right_wires = &wire_keys[gate.right.0];
            let output_wires = &wire_keys[gate.output.0];

            let garble_table = garble(left_wires, right_wires, output_wires, gate);
            let garbled_gate = GarbledGate::new(garble_table);

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

struct GarbledGate {
    map: HashMap<Vec<u8>, (Vec<u8>, Nonce<Aes256Gcm>)>,
}

impl GarbledGate {
    fn new(map: HashMap<Vec<u8>, (Vec<u8>, Nonce<Aes256Gcm>)>) -> Self {
        Self { map }
    }
}

struct GarbledCircuit {
    // Represents the input to the circuit
    // Each input belongs to a party
    inputs: Vec<Party>,
    outputs: Vec<Wire>,

    // The gates used in the circuit
    gates: Vec<GarbledGate>,

    // Wires in the circuit
    wires: Vec<InnerWire>,
    wire_keys: Vec<[Key<Aes256Gcm>; 2]>,
}

fn new_millionaires_circuit() -> Circuit {
    use crate::ops::*;

    let mut circuit = Circuit::new();
    let a_0 = circuit.add_input(Party(0));
    let a_1 = circuit.add_input(Party(0));
    let b_0 = circuit.add_input(Party(1));
    let b_1 = circuit.add_input(Party(1));

    // res = (a_0 > b_0) | ((a_0 == b_0) & (a_1 >= b_1))
    let a_0_gt_b_0 = circuit.add_gate(a_gt_b, a_0, b_0);
    let a_0_eq_b_0 = circuit.add_gate(a_eq_b, a_0, b_0);
    let a_1_geq_b_1 = circuit.add_gate(a_geq_b, a_1, b_1);
    let lower_and = circuit.add_gate(a_and_b, a_0_eq_b_0, a_1_geq_b_1);
    let upper_or = circuit.add_gate(a_or_b, a_0_gt_b_0, lower_and);
    circuit.add_output(upper_or);

    circuit
}

// TODO: clean up types...
fn garble(
    left_keys: &[Key<Aes256Gcm>; 2],
    right_keys: &[Key<Aes256Gcm>; 2],
    out_keys: &[Key<Aes256Gcm>; 2],
    gate: &Gate,
) -> HashMap<Vec<u8>, (Vec<u8>, Nonce<Aes256Gcm>)> {
    // TODO: cleanup...
    // construct the Garbled Gate table
    let mut result = HashMap::new();
    let inputs = vec![(0, 0), (0, 1), (1, 0), (1, 1)];

    for (left, right) in &inputs {
        let left_key = left_keys[*left];
        let right_key = right_keys[*right];
        let out_key = out_keys[(gate.op)(*left, *right)];

        // hash the corresponding keys
        let mut hasher = Sha256::new();
        hasher.update(left_key);
        hasher.update(right_key);
        let hash = hasher.finalize();

        // encrypt the output key
        let key = left_key
            .iter()
            .zip(right_key)
            .map(|(k1, k2)| k1 ^ k2)
            .collect::<Key<Aes256Gcm>>();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, &*out_key).unwrap();
        result.insert(hash[..].to_vec(), (ciphertext.into(), nonce));
    }

    result
}

// TODO: Error handling...
fn evaluate(
    garbled_gate: &HashMap<Vec<u8>, (Vec<u8>, Nonce<Aes256Gcm>)>,
    left_key: &Key<Aes256Gcm>,
    right_key: &Key<Aes256Gcm>,
) -> Key<Aes256Gcm> {
    let mut hasher = Sha256::new();
    hasher.update(left_key);
    hasher.update(right_key);
    let hash = hasher.finalize();

    let key = left_key
        .iter()
        .zip(right_key)
        .map(|(k1, k2)| k1 ^ k2)
        .collect::<Key<Aes256Gcm>>();

    let (ciphertext, nonce) = garbled_gate.get(&hash[..].to_vec()).unwrap();
    let cipher = Aes256Gcm::new(&key);
    let out_key = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    Key::<Aes256Gcm>::from_iter(out_key.into_iter())
}

fn decompose(value: usize, n: u32) -> Vec<usize> {
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

    #[test]
    fn millionaires_circuit_evaluates_correctly() {
        let millionaires = new_millionaires_circuit();
        let n = 2;

        for a in 0..2usize.pow(n) {
            for b in 0..2usize.pow(n) {
                let mut inputs = vec![];
                inputs.extend(decompose(a, n));
                inputs.extend(decompose(b, n));

                assert_eq!(
                    millionaires.evaluate(inputs.clone()),
                    vec![(a >= b) as usize],
                );
            }
        }
    }
}
