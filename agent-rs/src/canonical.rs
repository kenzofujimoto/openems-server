//! Canonical JSON identical to Python's
//! `json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
//! The server signs policies with that encoding, so the bytes must match.

use serde_json::{Number, Value};

pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => write_number(out, number),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Python sorts by code point; UTF-8 byte order is the same order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[key]);
            }
            out.push('}');
        }
    }
}

fn write_number(out: &mut String, number: &Number) {
    if let Some(integer) = number.as_i64() {
        out.push_str(&integer.to_string());
    } else if let Some(integer) = number.as_u64() {
        out.push_str(&integer.to_string());
    } else if let Some(float) = number.as_f64() {
        out.push_str(&python_float_repr(float));
    }
}

/// Python's `repr(float)`: shortest round-trip digits, fixed notation for
/// decimal exponents in [-4, 16), scientific with a signed two-digit exponent otherwise.
pub fn python_float_repr(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("LowerExp always has an exponent");
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i32 = exponent.parse().expect("LowerExp exponent is an integer");
    let point = exponent + 1;
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let length = digits.len() as i32;
    let body = if point <= -4 || point > 16 {
        let (first, rest) = digits.split_at(1);
        let fraction = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{first}{fraction}e{exp_sign}{:02}", exponent.abs())
    } else if point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else if point >= length {
        format!("{digits}{}.0", "0".repeat((point - length) as usize))
    } else {
        let (whole, fraction) = digits.split_at(point as usize);
        format!("{whole}.{fraction}")
    };
    format!("{sign}{body}")
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if (control as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", control as u32)),
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::python_float_repr;

    #[test]
    fn floats_follow_python_repr() {
        for (value, expected) in [
            (1.0, "1.0"), (100.0, "100.0"), (0.5, "0.5"), (-0.25, "-0.25"), (1e-5, "1e-05"),
            (0.0001, "0.0001"), (1e16, "1e+16"), (1e15, "1000000000000000.0"), (1.5e300, "1.5e+300"),
            (123456789.123, "123456789.123"), (-0.0, "-0.0"), (2.5e-7, "2.5e-07"), (0.1, "0.1"),
        ] {
            assert_eq!(python_float_repr(value), expected, "repr({value})");
        }
    }
}
