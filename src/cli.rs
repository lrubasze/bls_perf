use crate::bls12381::*;
use crate::calc;
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
/// Measure number of instructions of below commands
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

fn cli_measure_verify(cmd: &Verify) {
    let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data(1, 1, cmd.msg_size);

    println!("verify");
    let (_, _) = perf!(
        "total instructions",
        verify_bls12381_v1(&msgs[0], &pks[0], &sigs[0])
    );
    println!(
        "{:30}: {}",
        "calc_instructions",
        calc::calc_verify_instructions(cmd.msg_size)
    );
}

fn cli_measure_fast_aggregate_verify(cmd: &AggregateVerify) {
    let (_sks, pks, msg, sigs) = get_fast_aggregate_verify_test_data(cmd.msg_cnt, cmd.msg_size);

    // Aggregate the signature
    let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

    println!("fast_aggregate_verify");
    let (_, count) = perf!(
        "total_instructions",
        fast_aggregate_verify_bls12381_v1(&msg, &pks, &agg_sig)
    );
    let calc_instructions =
        calc::calc_fast_aggregate_verify_instructions(cmd.msg_cnt, cmd.msg_size);
    println!(
        "{:30}: {} diff: {}",
        "calc_instructions",
        calc_instructions,
        calc_instructions as i64 - count as i64
    );
}

fn cli_measure_aggregate_verify(
    threaded: bool,
    pub_keys_msgs: &[(Bls12381G1PublicKey, Vec<u8>)],
    agg_sig: &Bls12381G2Signature,
) {
    let sizes: Vec<usize> = pub_keys_msgs.iter().map(|(_, msg)| msg.len()).collect();

    let mut calc_instructions =
        calc::calc_aggregate_verify_instructions_no_threaded(sizes.as_slice());

    let (_, count) = if threaded {
        println!("aggregate_verify threaded");
        calc_instructions = calc::calc_aggregate_verify_instructions_threaded(calc_instructions);

        perf!(
            "total_instructions",
            aggregate_verify_bls12381_v1_threaded(pub_keys_msgs, agg_sig)
        )
    } else {
        println!("aggregate_verify");
        perf!(
            "total_instructions",
            aggregate_verify_bls12381_v1(pub_keys_msgs, agg_sig)
        )
    };

    let diff = if count != 0 {
        format!(" diff : {}", calc_instructions as i64 - count as i64)
    } else {
        "".to_string()
    };
    println!("{:30}: {}{}", "calc_instructions", calc_instructions, diff);
}

fn cli_cmd_measure_aggregate_verify(threaded: bool, cmd: &AggregateVerify) {
    let (_sks, pks, msgs, sigs) =
        get_aggregate_verify_test_data(cmd.msg_cnt, cmd.msg_cnt, cmd.msg_size);

    // Aggregate the signature
    let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

    let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
        pks.iter().zip(msgs).map(|(pk, sk)| (*pk, sk)).collect();

    cli_measure_aggregate_verify(threaded, &pub_keys_msgs, &agg_sig);
}

fn cli_measure_aggregate_verify_sizes(threaded: bool, cmd: &AggregateVerifySizes) {
    let (_sks, pks, msgs, sigs) = get_aggregate_verify_test_data2(&cmd.msg_sizes);

    // Aggregate the signature
    let agg_sig = Bls12381G2Signature::aggregate(&sigs).unwrap();

    let pub_keys_msgs: Vec<(Bls12381G1PublicKey, Vec<u8>)> =
        pks.iter().zip(msgs).map(|(pk, sk)| (*pk, sk)).collect();

    cli_measure_aggregate_verify(threaded, &pub_keys_msgs, &agg_sig);
}

fn cli_measure_signature_aggregate(cmd: &SignatureAggregate) {
    let (_sks, _pks, _msg, sigs) = get_fast_aggregate_verify_test_data(cmd.sig_cnt, 100);

    println!("signature_aggregate");
    let (_, count) = perf!("measured_sig_aggr", Bls12381G2Signature::aggregate(&sigs));
    let calc_instructions = calc::calc_signature_aggregate_instructions(cmd.sig_cnt);

    println!(
        "{:30}: {} diff: {}",
        "calc_instructions",
        calc_instructions,
        calc_instructions as i64 - count as i64
    );
}

fn cli_measure_hash_to_point(cmd: &HashToPoint) {
    let msg: Vec<u8> = vec![(cmd.msg_size % u8::MAX as usize) as u8; cmd.msg_size];

    println!("hash_to_point");
    perf!("total_instructions", hash_to_g2(&msg));
}

fn cli_measure_keccak256(cmd: &Verify) {
    let msg: Vec<u8> = vec![(cmd.msg_size % u8::MAX as usize) as u8; cmd.msg_size];

    println!("keccak25");
    perf!("total_instructions", keccak256_hash(&msg));
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
