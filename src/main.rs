/*
use count_instructions::count_instructions;

fn add(left: usize, right: usize) -> usize {
    left + right
}

fn main() {
    println!("Hello, world!");

    let mut count = 0;
    //let mut addresses = Vec::new();
    let result = count_instructions(
        || {
            println!("count = {} {}", 2, 3);
            //println!("count = {}", 2);
            add(2, 2);
            add(3, 5)
        },
        |_instruction| {
            count += 1;
            //addresses.push(instruction.address());
        },
    )
    .unwrap();
    assert_eq!(result, 8);
    assert_ne!(count, 0);
    println!("count = {count}");
    //println!("addresses = {:?}", addresses);
}
*/
//mod error;
mod bls12381;
mod cli;
#[macro_use]
mod utils;

pub use bls12381::*;
pub use utils::*;

fn main() {
    cli::run()
}
