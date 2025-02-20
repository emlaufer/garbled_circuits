pub fn a_eq_b(a: usize, b: usize) -> usize {
    (a == b) as usize
}

pub fn a_gt_b(a: usize, b: usize) -> usize {
    (a > b) as usize
}

pub fn a_geq_b(a: usize, b: usize) -> usize {
    (a >= b) as usize
}

pub fn a_and_b(a: usize, b: usize) -> usize {
    a & b
}

pub fn a_or_b(a: usize, b: usize) -> usize {
    a | b
}
