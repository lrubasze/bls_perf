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

pub fn calc_aggregate_verify_instructions_no_threaded(sizes: &[usize]) -> u32 {
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

pub fn calc_aggregate_verify_instructions_threaded(no_threaded_instructions: u32) -> u32 {
    // Observed that threaded takes ~1.21 more instructions than no threaded
    mul(no_threaded_instructions / 100, 121)
}

pub fn calc_verify_instructions(size: usize) -> u32 {
    add(mul(cast(size), 36), 15650000)
}

pub fn calc_fast_aggregate_verify_instructions(cnt: u32, size: usize) -> u32 {
    add(add(mul(cast(size), 36), mul(cnt, 626056)), 15200000)
}

pub fn calc_signature_aggregate_instructions(cnt: u32) -> u32 {
    sub(mul(cnt, 879554), 500000)
}
