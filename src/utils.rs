/// Copies a slice to a fixed-sized array.
pub fn copy_u8_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    if slice.len() == N {
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        bytes
    } else {
        panic!("Invalid length: expected {}, actual {}", N, slice.len());
    }
}

#[macro_export]
macro_rules! measure {
    ($desc:expr, $closure:expr) => {
        let mut count = 0;
        let _result = count_instructions::count_instructions(
            || {
                $closure;
            },
            |_instruction| {
                count += 1;
                //addresses.push(instruction.address());
            },
        )
        .unwrap();
        println!("{:20} instr:{:?}", $desc, count);
    };
}

#[macro_export]
macro_rules! perf {
    ($desc:expr, $closure:expr) => {{
        let method = $crate::cli::MEASURE_METHOD
            .get_or_init(|| std::sync::Mutex::new(String::new()))
            .lock()
            .unwrap()
            .clone();
        match method.as_ref() {
            "count" => {
                let mut count = 0;
                let result = count_instructions::count_instructions(
                    || $closure,
                    |_instruction| {
                        count += 1;
                    },
                )
                .unwrap();
                println!("{:30}: {:?}", $desc, count);
                (result, count)
            }
            "perf" => {
                let mut insns = perf_event::Builder::new()
                    .kind(perf_event::events::Hardware::INSTRUCTIONS)
                    .inherit(true) // whether to inherit counter by new threads
                    .build()
                    .unwrap();

                insns.enable().unwrap();
                let result = $closure;
                insns.disable().unwrap();

                let counts = insns.read().unwrap();
                println!("{:30}: {:?}", $desc, counts);
                (result, counts)
            }
            "none" => ($closure, 0),
            _ => panic!("measure method {:?} not supported", method),
        }
    }};
}
