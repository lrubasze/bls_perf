use crate::bls12381::*;
use crate::keccak256_hash;
use crate::perf;
use clap::{Parser, Subcommand};
use once_cell::sync::OnceCell;
use std::sync::Mutex;

const MEASURE_METHOD_DFLT: &str = "perf";

pub static MEASURE_METHOD: OnceCell<Mutex<String>> = OnceCell::new();

#[derive(Parser)]
#[command(author, version, about, long_about, verbatim_doc_comment)]
#[command(propagate_version = true)]
struct Cli {
    #[arg(long, short = 'm', default_value_t = MEASURE_METHOD_DFLT.to_string())]
    /// available methods: perf, count, none
    /// for 'perf' method following command shall be issued:
    ///   sudo bash -c "echo -1 > /proc/sys/kernel/perf_event_paranoid"
    measure_method: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Parser)]
struct Verify {
    #[arg(long, short = 's', default_value_t = 1024)]
    msg_size: usize,
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
struct SignatureAggregate {
    #[arg(long, short = 'c', default_value_t = 10)]
    sig_cnt: u32,
}

#[derive(Debug, Parser)]
struct HashToPoint {
    #[arg(long, short = 's', default_value_t = 1024)]
    msg_size: usize,
}

#[derive(Subcommand)]
enum Commands {
    Verify(Verify),
    AggregateVerify(AggregateVerify),
    AggregateVerifySizes(AggregateVerifySizes),
    AggregateVerifyThreaded(AggregateVerify),
    FastAggregateVerify(AggregateVerify),
    SignatureAggregate(SignatureAggregate),
    HashToPoint(HashToPoint),
    Keccak256(Verify),
}
/*
#[inline]
fn cast<T>(a: T) -> u32
where
    u32: TryFrom<T>,
{
    u32::try_from(a).unwrap()
}
*/
#[inline]
fn cast(a: usize) -> u32 {
    u32::try_from(a).unwrap()
}

#[inline]
fn add(a: u32, b: u32) -> u32 {
    a.checked_add(b).unwrap()
}

#[inline]
fn sub(a: u32, b: u32) -> u32 {
    a.checked_sub(b).unwrap()
}

#[inline]
fn mul(a: u32, b: u32) -> u32 {
    a.checked_mul(b).unwrap()
}

fn calc_aggregate_verify_instructions_no_threaded(sizes: &[usize]) -> u32 {
    let mut instructions_cnt = 0;
    for s in sizes {
        instructions_cnt = add(add(instructions_cnt, mul(35, cast(*s))), 2620296);
    }
    let multiplier = cast(sizes.len() / 8);

    instructions_cnt = add(instructions_cnt, mul(multiplier, 16850000));

    // Pairing commit
    // Observed that number commit instructions repeats every multiple of 8
    instructions_cnt = add(
        instructions_cnt,
        match sizes.len() % 8 {
            0 => 0,
            1 => 3051556,
            2 => 5020768,
            3 => 6990111,
            4 => 8959454,
            5 => 10928798,
            6 => 12898141,
            7 => 14867484,
            _ => unreachable!(),
        },
    );

    // Instructions that do not depend on size
    instructions_cnt = add(instructions_cnt, 281125 + 583573 + 3027639 + 4280077);
    instructions_cnt
}

fn calc_aggregate_verify_instructions_threaded(no_threaded_instructions: u32) -> u32 {
    // Observed that threaded takes ~1.21 more instructions than no threaded
    mul(no_threaded_instructions / 100, 121)
}

fn verify_instructions(size: usize) -> u32 {
    add(mul(cast(size), 36), 15650000)
}

fn fast_aggregate_verify_instructions(cnt: u32, size: usize) -> u32 {
    add(add(mul(cast(size), 36), mul(cnt, 626056)), 15200000)
}
fn signature_aggregate_instructions(cnt: u32) -> u32 {
    sub(mul(cnt, 879554), 500000)
}

fn cli_measure_verify(cmd: &Verify) {
    let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data(1, 1, cmd.msg_size);

    let (_, _) = perf!("total agg", verify_bls12381_v1(&msgs[0], &pks[0], &sigs[0]));
    println!(
        "{:20} instr:{}",
        "total threaded",
        verify_instructions(cmd.msg_size),
    );
}

fn cli_measure_fast_aggregate_verify(cmd: &AggregateVerify) {
    let (_sks, pks, msg, sigs) = get_fast_aggregate_verify_test_data(cmd.msg_cnt, cmd.msg_size);

    // Aggregate the signature
    let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

    let (_, _) = perf!(
        "total agg",
        fast_aggregate_verify_bls12381_v1(&msg, &pks, &agg_sig)
    );
    println!(
        "{:20} instr:{}",
        "total threaded",
        fast_aggregate_verify_instructions(cmd.msg_cnt, cmd.msg_size),
    );
}

fn cli_measure_aggregate_verify(
    threaded: bool,
    pub_keys_msgs: &[(Bls12381G1PublicKey, Vec<u8>)],
    agg_sig: &Bls12381G2Signature,
) {
    let sizes: Vec<usize> = pub_keys_msgs.iter().map(|(_, msg)| msg.len()).collect();

    let no_threaded_instructions = calc_aggregate_verify_instructions_no_threaded(sizes.as_slice());
    let threaded_instructions =
        calc_aggregate_verify_instructions_threaded(no_threaded_instructions);

    if threaded {
        let (_, count) = perf!(
            "total_instructions_threaded",
            aggregate_verify_bls12381_v1_threaded(pub_keys_msgs, agg_sig)
        );
        println!(
            "{:30}: {}",
            "calc_instructions_no_threaded", no_threaded_instructions
        );
        let diff = if count != 0 {
            format!(" diff: {}", threaded_instructions as i64 - count as i64)
        } else {
            "".to_string()
        };
        println!(
            "{:30}: {}{}",
            "calc_instructions_threaded", threaded_instructions, diff
        );
    } else {
        let (_, count) = perf!(
            "total_instructions_no_threaded",
            aggregate_verify_bls12381_v1(pub_keys_msgs, agg_sig)
        );
        let diff = if count != 0 {
            format!(" diff : {}", no_threaded_instructions as i64 - count as i64)
        } else {
            "".to_string()
        };
        println!(
            "{:30}: {}{}",
            "calc_instructions_no_threaded", no_threaded_instructions, diff
        );
        println!(
            "{:30}: {}",
            "calc_instructions_threaded", threaded_instructions
        );
    }
}

fn cli_cmd_measure_aggregate_verify(threaded: bool, cmd: &AggregateVerify) {
    let (_sks, pks, msgs, sigs) =
        get_aggregate_verify_test_data(cmd.msg_cnt, cmd.msg_cnt, cmd.msg_size);

    // Aggregate the signature
    let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

    let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
        pks.iter().zip(msgs).map(|(pk, sk)| (*pk, sk)).collect();

    println!("aggregate_verify");
    cli_measure_aggregate_verify(threaded, &pub_keys_msgs, &agg_sig);
}

fn cli_measure_aggregate_verify_sizes(threaded: bool, cmd: &AggregateVerifySizes) {
    let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data2(&cmd.msg_sizes);

    // Aggregate the signature
    let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

    let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
        pks.iter().zip(msgs).map(|(pk, sk)| (*pk, sk)).collect();

    println!("aggregate_verify_sizes");
    cli_measure_aggregate_verify(threaded, &pub_keys_msgs, &agg_sig);
}

fn cli_measure_signature_aggregate(cmd: &SignatureAggregate) {
    let (_sks, _pks, _msg, sigs) = get_fast_aggregate_verify_test_data(cmd.sig_cnt, 100);

    let (_, count) = perf!("measured_sig_aggr", Bls12381G2Signature::aggregate(&sigs));
    let calc_sig_aggr_instr_cnt = signature_aggregate_instructions(cmd.sig_cnt);

    println!(
        "{:20} instr:{} diff:{}",
        "calc_sig_agr",
        calc_sig_aggr_instr_cnt,
        calc_sig_aggr_instr_cnt as i64 - count as i64
    );
}

fn cli_measure_hash_to_point(cmd: &HashToPoint) {
    let msg: Vec<u8> = vec![(cmd.msg_size % u8::MAX as usize) as u8; cmd.msg_size];

    perf!("hash_to_point", hash_to_g2(&msg));
}

fn cli_measure_keccak256(cmd: &Verify) {
    let msg: Vec<u8> = vec![(cmd.msg_size % u8::MAX as usize) as u8; cmd.msg_size];

    perf!("measured_keccak256", keccak256_hash(&msg));
}

pub fn run() {
    let cli = Cli::parse();

    *MEASURE_METHOD
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
        .unwrap() = cli.measure_method;

    match &cli.command {
        Commands::Verify(args) => {
            cli_measure_verify(args);
        }
        Commands::AggregateVerify(args) => {
            cli_cmd_measure_aggregate_verify(false, args);
        }
        Commands::AggregateVerifySizes(args) => {
            cli_measure_aggregate_verify_sizes(false, args);
        }
        Commands::AggregateVerifyThreaded(args) => {
            cli_cmd_measure_aggregate_verify(true, args);
        }
        Commands::FastAggregateVerify(args) => {
            cli_measure_fast_aggregate_verify(args);
        }
        Commands::SignatureAggregate(args) => {
            cli_measure_signature_aggregate(args);
        }
        Commands::HashToPoint(args) => {
            cli_measure_hash_to_point(args);
        }
        Commands::Keccak256(args) => {
            cli_measure_keccak256(args);
        }
    }
}
