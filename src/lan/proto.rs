//! Small, bounded protobuf reader for the Remote Play messages we use.
use anyhow::{Result, bail, ensure};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value<'a> {
    Number(u64),
    Bytes(&'a [u8]),
}

pub fn fields(mut data: &[u8]) -> Result<Vec<(u32, Value<'_>)>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let tag = varint(&mut data)?;
        ensure!(
            tag >> 3 > 0 && tag >> 3 <= 0x1fff_ffff,
            "invalid protobuf field"
        );
        let value = match tag & 7 {
            0 => Value::Number(varint(&mut data)?),
            1 => Value::Number(u64::from_le_bytes(take(&mut data, 8)?.try_into()?)),
            2 => {
                let len = usize::try_from(varint(&mut data)?)?;
                Value::Bytes(take(&mut data, len)?)
            }
            5 => Value::Number(u32::from_le_bytes(take(&mut data, 4)?.try_into()?) as u64),
            _ => bail!("unsupported protobuf wire type"),
        };
        out.push(((tag >> 3) as u32, value));
    }
    Ok(out)
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    ensure!(n <= data.len(), "truncated protobuf field");
    let (head, tail) = data.split_at(n);
    *data = tail;
    Ok(head)
}

fn varint(data: &mut &[u8]) -> Result<u64> {
    let mut out = 0;
    for shift in (0..70).step_by(7) {
        let byte = take(data, 1)?[0];
        ensure!(shift != 63 || byte <= 1, "protobuf varint overflow");
        out |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Ok(out);
        }
    }
    bail!("protobuf varint overflow")
}

pub fn number(data: &[u8], field: u32) -> Result<Option<u64>> {
    Ok(fields(data)?.into_iter().rev().find_map(|(f, v)| match v {
        Value::Number(n) if f == field => Some(n),
        _ => None,
    }))
}

pub fn bytes(data: &[u8], field: u32) -> Result<Option<&[u8]>> {
    Ok(fields(data)?.into_iter().rev().find_map(|(f, v)| match v {
        Value::Bytes(b) if f == field => Some(b),
        _ => None,
    }))
}

fn put_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 128 {
        out.push(n as u8 | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
pub fn uint(out: &mut Vec<u8>, field: u32, n: u64) {
    put_varint(out, u64::from(field) << 3);
    put_varint(out, n);
}
pub fn fixed(out: &mut Vec<u8>, field: u32, n: u64) {
    put_varint(out, u64::from(field) << 3 | 1);
    out.extend(n.to_le_bytes());
}
pub fn blob(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    put_varint(out, u64::from(field) << 3 | 2);
    put_varint(out, b.len() as u64);
    out.extend(b);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_wire_fixture_and_malformed_packets() {
        // ssid="hi", supports_progress=true, followed by unknown fixed64 field.
        let wire = [0x0a, 2, b'h', b'i', 0x18, 1, 0x29, 8, 7, 6, 5, 4, 3, 2, 1];
        assert_eq!(bytes(&wire, 1).unwrap(), Some(b"hi".as_slice()));
        assert_eq!(number(&wire, 5).unwrap(), Some(0x0102030405060708));
        for bad in [
            &[0][..],
            &[0x0a, 5, 1],
            &[0x09, 1],
            &[
                0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2,
            ],
        ] {
            assert!(fields(bad).is_err());
        }
    }
}
