//! Strict MQTT UTF-8 String validator conforming to [MQTT-1.5.4-1] and [MQTT-1.5.4-2].
//! Must NOT contain null character U+0000, nor Unicode non-characters, nor surrogates.

use crate::error::{MqttError, Result};

#[inline]
pub fn validate_mqtt_utf8(s: &str) -> Result<()> {
    for c in s.chars() {
        // [MQTT-1.5.4-2] Character data MUST NOT include the null character U+0000
        if c == '\0' {
            return Err(MqttError::InvalidUtf8);
        }
        // Check for disallowed unicode non-characters [MQTT-1.5.4-1]
        let u = c as u32;
        if (0xFDD0..=0xFDEF).contains(&u) || (u & 0xFFFE) == 0xFFFE {
            return Err(MqttError::InvalidUtf8);
        }
    }
    Ok(())
}
