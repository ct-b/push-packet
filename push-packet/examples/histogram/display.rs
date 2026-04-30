pub fn format_bytes(b: usize) -> String {
    const K: f64 = 1000.0;
    let b = b as f64;
    if b < K {
        format!("{} B", b as usize)
    } else if b < K * K {
        format!("{:.1} KB", b / K)
    } else if b < K * K * K {
        format!("{:.1} MB", b / (K * K))
    } else {
        format!("{:.2} GB", b / (K * K * K))
    }
}

pub fn format_cells(data: &[String], maxes: &[usize], gap: usize, width: usize) -> String {
    let mut terms = vec![];
    let mut total = 0;
    for (i, value) in data.iter().enumerate() {
        let max = maxes[i];
        let value = format!("{:>width$}", value, width = max);
        let mut len = value.len();
        if i != data.len() - 1 {
            len += gap;
        }
        if total + len >= width {
            break;
        }
        terms.push(value);
        total += len;
    }
    let rem = terms.iter().fold(width, |mut acc, term| {
        acc -= term.len();
        acc
    });
    let div = rem / (terms.len() - 1).max(1);
    let mut output = String::new();
    terms.iter().enumerate().for_each(|(i, term)| {
        output.push_str(term);
        if i < terms.len() {
            output.push_str(&" ".repeat(div));
        }
    });
    output
}
