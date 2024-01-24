use crate::bls12381::*;
use crate::perf;
use clap::{Parser, Subcommand};
use once_cell::sync::OnceCell;
use std::sync::Mutex;
use std::{thread, time};

const MEASURE_METHOD_DFLT: &str = "perf";

pub static MEASURE_METHOD: OnceCell<Mutex<String>> = OnceCell::new();

#[derive(Parser)]
#[command(author, version, about, long_about, verbatim_doc_comment)]
#[command(propagate_version = true)]
struct Cli {
    #[arg(long, short = 'm', default_value_t = MEASURE_METHOD_DFLT.to_string())]
    measure_method: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Parser)]
struct AggregateVerify {
    #[arg(long, short = 's', default_value_t = 1024)]
    msg_size: usize,
    #[arg(long, short = 'c', default_value_t = 10)]
    msg_cnt: u32,
}

#[derive(Debug, Parser)]
struct AggregateVerifySizes {
    #[arg(long, short, use_value_delimiter = true, value_delimiter = ',', default_values_t = vec![100, 100, 100, 100000, 100000])]
    msg_sizes: Vec<usize>,
}

#[derive(Debug, Parser)]
struct HashToPoint {
    #[arg(long, short = 's', default_value_t = 1024)]
    msg_size: usize,
}

#[derive(Subcommand)]
enum Commands {
    AggregateVerify(AggregateVerify),
    AggregateVerifySizes(AggregateVerifySizes),
    AggregateVerifyThreaded(AggregateVerify),
    HashToPoint(HashToPoint),
}

#[inline]
fn cast<T>(a: T) -> u32
where
    u32: TryFrom<T>,
{
    u32::try_from(a).unwrap_or(u32::MAX)
}

fn pairing_aggregate_costs(input_sizes: &[usize]) -> u32 {
    // ŷ = 34.42199X + 2620295.64271
    // y = 35 * x + 2620296
    // Observed that every 7th key additional 16850000 are performed
    let mut costs = 0usize;

    for s in input_sizes {
        costs += 35 * s + 2620296;
    }
    let mut multiplier = input_sizes.len() / 7;
    /*
        let mut m = input_sizes.len() as i32 % 7;
        let mut d = (input_sizes.len() / 7) as i32;

        println!(
            "len: {} multiplier: {} m: {} d: {}",
            input_sizes.len(),
            multiplier,
            m,
            d
        );

        if d > 7 {
            multiplier -= usize::try_from(d).unwrap() / 7;
            d = d % 7; // - 1;
        }

        if m < d {
            multiplier -= 1;
        }

        println!(
            "pa:{} m:{} d:{} d%7:{} cond1:{:?} cond2:{:?} multiplier: {}",
            costs,
            m,
            d,
            d % 7,
            (m >= d % 7),
            m < d,
            multiplier
        );
    */
    costs += multiplier * 16850000;

    println!("pa:{} multiplier: {}", costs, multiplier);
    //println!("pa:{} ", costs);
    cast(costs)
}

fn pairing_commit_costs(input_sizes: &[usize]) -> u32 {
    let costs = match input_sizes.len() % 8 {
        1 => 3051556_u32,
        2 => 5020768_u32,
        3 => 6990111_u32,
        4 => 8959454_u32,
        5 => 10928798_u32,
        6 => 12898141_u32,
        7 => 14867484_u32,
        0 => 0,
        _ => unreachable!(),
    };
    println!("pc:{}", costs);
    costs
}

fn total_costs_no_threaded(input_sizes: &[usize]) -> u32 {
    let mut costs = pairing_aggregate_costs(input_sizes);
    costs += pairing_commit_costs(input_sizes);

    // Operations that do not depend on input size
    // Signature from bytes : 281125 instructions
    // Signature Validate   : 583573
    // Pairing Aggregated   : 3027639
    // Pairing finalVerify  : 4280077
    costs += 281125 + 583573 + 3027639 + 4280077;
    costs
}

fn total_costs_threaded(no_threaded_instructions: u32) -> u32 {
    // Observed that threaded takes ~1.21 more instructions than no threaded
    let instructions: u64 = (no_threaded_instructions as u64 * 121) / 100;
    cast(instructions)
}

fn cli_measure_aggregate_verify(threaded: bool, cmd: &AggregateVerify) {
    let (_sks, pks, msgs, sigs) =
        get_aggregate_verify_test_data(cmd.msg_cnt, cmd.msg_cnt, cmd.msg_size);

    // Aggregate the signature
    let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

    let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
        pks.iter().zip(msgs).map(|(pk, sk)| (*pk, sk)).collect();

    // Verify the messages against public keys and aggregated signature
    //measure!(aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig));
    /*
        println!("waiting");
        let wait_secs = time::Duration::from_secs(2);

        thread::sleep(wait_secs);
        println!("go");
    */
    let sizes: Vec<usize> = pub_keys_msgs.iter().map(|(_, msg)| msg.len()).collect();
    let no_threaded_instructions = total_costs_no_threaded(sizes.as_slice());
    let threaded_instructions = total_costs_threaded(no_threaded_instructions);

    if threaded {
        let (_, count) = perf!(
            "total agg",
            aggregate_verify_bls12381_v1_threaded(&pub_keys_msgs, &agg_sig)
        );
        println!(
            "{:20} instr:{}",
            "total no-threaded", no_threaded_instructions
        );
        println!(
            "{:20} instr:{}: diff:{}",
            "total threaded",
            threaded_instructions,
            threaded_instructions as i64 - count as i64
        );
    } else {
        let (_, count) = perf!(
            "total agg",
            aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig)
        );
        println!(
            "{:20} instr:{} diff:{}",
            "total no-threaded",
            no_threaded_instructions,
            no_threaded_instructions as i64 - count as i64
        );
        println!("{:20} instr:{}", "total threaded", threaded_instructions);
    }
}

fn cli_measure_aggregate_verify_sizes(threaded: bool, cmd: &AggregateVerifySizes) {
    let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data2(&cmd.msg_sizes);

    // Aggregate the signature
    let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

    let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
        pks.iter().zip(msgs).map(|(pk, sk)| (*pk, sk)).collect();

    // Verify the messages against public keys and aggregated signature
    //measure!(aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig));
    /*
        println!("waiting");
        let wait_secs = time::Duration::from_secs(2);

        thread::sleep(wait_secs);
        println!("go");
    */
    //let sizes: Vec<usize> = pub_keys_msgs.iter().map(|(_, msg)| msg.len()).collect();
    let no_threaded_instructions = total_costs_no_threaded(cmd.msg_sizes.as_slice());
    let threaded_instructions = total_costs_threaded(no_threaded_instructions);

    if threaded {
        let (_, count) = perf!(
            "total agg",
            aggregate_verify_bls12381_v1_threaded(&pub_keys_msgs, &agg_sig)
        );
        println!(
            "{:20} instr:{}",
            "total no-threaded", no_threaded_instructions
        );
        println!(
            "{:20} instr:{}: diff:{}",
            "total threaded",
            threaded_instructions,
            threaded_instructions as i64 - count as i64
        );
    } else {
        let (_, count) = perf!(
            "total agg",
            aggregate_verify_bls12381_v1(&pub_keys_msgs, &agg_sig)
        );
        println!(
            "{:20} instr:{} diff:{}",
            "total no-threaded",
            no_threaded_instructions,
            no_threaded_instructions as i64 - count as i64
        );
        println!("{:20} instr:{}", "total threaded", threaded_instructions);
    }
}

fn cli_measure_hash_to_point(cmd: &HashToPoint) {
    let msg: Vec<u8> = vec![(cmd.msg_size % u8::MAX as usize) as u8; cmd.msg_size];

    perf!("hash_to_point", hash_to_g2(&msg));
}

pub fn run() {
    let cli = Cli::parse();

    *MEASURE_METHOD
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
        .unwrap() = cli.measure_method;

    match &cli.command {
        Commands::AggregateVerify(args) => {
            cli_measure_aggregate_verify(false, args);
        }
        Commands::AggregateVerifySizes(args) => {
            cli_measure_aggregate_verify_sizes(false, args);
        }
        Commands::AggregateVerifyThreaded(args) => {
            cli_measure_aggregate_verify(true, args);
        }
        Commands::HashToPoint(args) => {
            cli_measure_hash_to_point(args);
        }
    }
}
