//! Zero-copy wire byte decoding and encoding helpers.
//! Conforming to ISO/IEC 20922:2016 and OASIS MQTT 5.0 Variable Byte Integer rules.

use crate::error::{MqttError, Result};

/// Decodes Variable Byte Integer according to MQTT Spec [MQTT-1.5.5-1].
/// Returns `(value, bytes_consumed)`.
#[inline]
pub fn decode_varint(buf: &[u8]) -> Result<(usize, usize)> {
    let mut multiplier: usize = 1;
    let mut value: usize = 0;
    let mut bytes_consumed = 0;

    for &byte in buf {
        bytes_consumed += 1;
        value += ((byte & 0x7F) as usize) * multiplier;
        if multiplier > 128 * 128 * 128 {
            return Err(MqttError::InvalidRemainingLength);
        }
        multiplier *= 128;
        if (byte & 0x80) == 0 {
            return Ok((value, bytes_consumed));
        }
        if bytes_consumed >= 4 {
            return Err(MqttError::InvalidRemainingLength);
        }
    }

    Err(MqttError::IncompletePacket)
}

/// Encodes a usize value into Variable Byte Integer.
/// Returns the number of bytes written.
#[inline]
pub fn encode_varint(mut value: usize, out: &mut [u8]) -> Result<usize> {
    if value > 268_435_455 {
        return Err(MqttError::InvalidRemainingLength);
    }
    let mut idx = 0;
    loop {
        if idx >= out.len() {
            return Err(MqttError::BufferTooSmall);
        }
        let mut encoded_byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            encoded_byte |= 0x80;
        }
        out[idx] = encoded_byte;
        idx += 1;
        if value == 0 {
            break;
        }
    }
    Ok(idx)
}

/// Reads a 2-byte big-endian u16 integer [MQTT-1.5.1].
#[inline]
pub fn read_u16(buf: &[u8]) -> Result<u16> {
    if buf.len() < 2 {
        return Err(MqttError::IncompletePacket);
    }
    Ok(u16::from_be_bytes([buf[0], buf[1]]))
}

/// Reads an MQTT UTF-8 Encoded String [MQTT-1.5.4].
/// Slices directly into input buffer without allocation.
#[inline]
pub fn read_string<'a>(buf: &'a [u8]) -> Result<(&'a str, usize)> {
    if buf.len() < 2 {
        return Err(MqttError::IncompletePacket);
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return Err(MqttError::IncompletePacket);
    }
    let slice = &buf[2..2 + len];
    let s = core::str::from_utf8(slice).map_err(|_| MqttError::InvalidUtf8)?;
    Ok((s, 2 + len))
}

/// Reads a 2-byte length-prefixed binary slice.
#[inline]
pub fn read_binary<'a>(buf: &'a [u8]) -> Result<(&'a [u8], usize)> {
    if buf.len() < 2 {
        return Err(MqttError::IncompletePacket);
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return Err(MqttError::IncompletePacket);
    }
    Ok((&buf[2..2 + len], 2 + len))
}
