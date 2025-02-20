use garbled_circuits::{new_millionaires_circuit, GarbledCircuit};

fn main() {
    let circuit = new_millionaires_circuit(2);

    let inputs = vec![0, 0];
    GarbledCircuit::evaluator(&circuit, inputs);
}
