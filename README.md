# Garbled Circuit Implementation

To run the programs, call:

`cargo run --example alice`
and
`cargo run --example bob`

The programs communicate over a file called `comm.txt`,
and will prompt you to indicate when certain values have
been written.
For example, the bob program might say "Press enter once the message \[input 0\] is written...".
This means you should wait for the alice program to say "Wrote message [input 1].." before continuing.

Alice and Bob are implemented in `examples/alice.rs` and `examples/bob.rs`.
To modify the bit-width of the millionaires circuit,
change the argument in

```let circuit = new_millionaires_circuit(2);```

to the desired bit-width

To modify the inputs to the circuit,
change 

```let inputs = vec![1, 0];```

This should be a bit-decomposition of the input.

## Organization

- `examples/alice.rs` - The alice program (Garbler)
- `examples/bob.rs` - The bob program (Evaluator)
- `src/lib.rs` - Contains the Garbled Circuit implementation
- `src/ot.rs` - Contains the Oblivious Transfer implementation
- `src/io.rs` - Implements the file-based communication
- `src/ops.rs` - Contains the gate op functions that are used within the circuit
