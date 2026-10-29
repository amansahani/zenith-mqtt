//! Zenith Core MQTT Error types (no_std compatible)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttError {
    /// Incomplete packet buffer - needs more bytes from network
    IncompletePacket,
    /// Malformed packet / protocol violation
    MalformedPacket,
    /// Unsupported MQTT protocol version
    UnsupportedProtocolVersion(u8),
    /// Invalid UTF-8 string found in packet
    InvalidUtf8,
    /// Buffer too small for serialization
    BufferTooSmall,
    /// Remaining length exceeds 4 bytes (MQTT spec limit 268,435,455 bytes)
    InvalidRemainingLength,
    /// Packet exceeds configured maximum size limit (Slowloris/DoS prevention)
    PacketTooLarge,
}

pub type Result<T> = core::result::Result<T, MqttError>;
