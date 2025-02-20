//! Helpers for using the file for communication

use std::fs::File;
use std::io::prelude::*;
use std::io::Write;

/// Write a message to the file
pub fn write_message(message: &[u8], context: &str) {
    let mut comm_file = File::create("comm.txt").unwrap();
    comm_file.write_all(message).unwrap();
    println!("Wrote message [{}]..", context);
}

/// Read a message
pub fn read_message() -> Vec<u8> {
    let mut comm_file = File::open("comm.txt").unwrap();
    let mut buffer = Vec::new();
    comm_file.read_to_end(&mut buffer).unwrap();
    return buffer;
}

/// Wait for a message be written
pub fn wait_for_message(context: &str) {
    println!("Press enter once the message [{}] is written...", context);
    std::io::stdin().read_line(&mut String::new()).unwrap();
}

/// Wait for a message be read
pub fn wait_for_read(context: &str) {
    println!("Press enter once the message [{}] is read...", context);
    std::io::stdin().read_line(&mut String::new()).unwrap();
}
