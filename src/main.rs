mod bls12381;
mod cli;
#[macro_use]
mod utils;
mod calc;
mod keccak256;

pub use bls12381::*;
pub use keccak256::*;
pub use utils::*;

fn main() {
    cli::run()
}
