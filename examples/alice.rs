use garbled_circuits::new_millionaires_circuit;

fn main() {
    let circuit = new_millionaires_circuit(2);
    let garbled = circuit.garble();

    let inputs = vec![1, 0];
    let outputs = garbled.garbler(inputs);
    println!("Got outputs: {:?}", outputs);
}
