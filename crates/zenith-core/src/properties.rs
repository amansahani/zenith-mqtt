//! OASIS MQTT 5.0 Properties and Reason Codes.
//! Zero-copy property parser supporting User Properties, Expiry, Content Type, etc.

use crate::error::{MqttError, Result};
use crate::wire::{decode_varint, read_binary, read_string, read_u16};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PropertyId {
    PayloadFormatIndicator = 0x01,
    MessageExpiryInterval = 0x02,
    ContentType = 0x03,
    ResponseTopic = 0x08,
    CorrelationData = 0x09,
    SubscriptionIdentifier = 0x0B,
    SessionExpiryInterval = 0x11,
    AssignedClientIdentifier = 0x12,
    ServerKeepAlive = 0x13,
    AuthenticationMethod = 0x15,
    AuthenticationData = 0x16,
    RequestProblemInformation = 0x17,
    WillDelayInterval = 0x18,
    RequestResponseInformation = 0x19,
    ResponseInformation = 0x1A,
    ServerReference = 0x1C,
    ReasonString = 0x1F,
    ReceiveMaximum = 0x21,
    TopicAliasMaximum = 0x22,
    TopicAlias = 0x23,
    MaximumQoS = 0x24,
    RetainAvailable = 0x25,
    UserProperty = 0x26,
    MaximumPacketSize = 0x27,
    WildcardSubscriptionAvailable = 0x28,
    SubscriptionIdentifierAvailable = 0x29,
    SharedSubscriptionAvailable = 0x2A,
}

/// Zero-copy parsed view of MQTT 5.0 User Property key-value pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProperty<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

/// Zero-copy parsed MQTT 5.0 properties for PUBLISH or CONNECT
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mqtt5Properties<'a> {
    pub message_expiry_interval: Option<u32>,
    pub content_type: Option<&'a str>,
    pub response_topic: Option<&'a str>,
    pub correlation_data: Option<&'a [u8]>,
    pub user_properties_count: usize,
    pub session_expiry_interval: Option<u32>,
    pub server_keep_alive: Option<u16>,
}

/// MQTT 5.0 Reason Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReasonCode {
    Success = 0x00,
    GrantedQoS1 = 0x01,
    GrantedQoS2 = 0x02,
    DisconnectWithWill = 0x04,
    NoMatchingSubscribers = 0x10,
    UnspecifiedError = 0x80,
    MalformedPacket = 0x81,
    ProtocolError = 0x82,
    NotAuthorized = 0x87,
    ServerBusy = 0x89,
    BadAuthenticationMethod = 0x8C,
    TopicFilterInvalid = 0x8F,
    TopicNameInvalid = 0x90,
    PacketIdentifierInUse = 0x91,
    QuotaExceeded = 0x97,
}

/// Zero-copy iterator/parser over MQTT 5.0 property slice.
/// Slices directly without heap allocation.
pub fn parse_properties<'a>(buf: &'a [u8]) -> Result<(Mqtt5Properties<'a>, usize)> {
    if buf.is_empty() {
        return Ok((Mqtt5Properties::default(), 0));
    }

    let (prop_len, varint_len) = decode_varint(buf)?;
    let total_len = varint_len + prop_len;

    if buf.len() < total_len {
        return Err(MqttError::IncompletePacket);
    }

    let mut props = Mqtt5Properties::default();
    let mut cursor = &buf[varint_len..total_len];

    while !cursor.is_empty() {
        let prop_id = cursor[0];
        cursor = &cursor[1..];

        match prop_id {
            0x02 => {
                // Message Expiry Interval (4-byte integer)
                if cursor.len() < 4 {
                    return Err(MqttError::MalformedPacket);
                }
                props.message_expiry_interval = Some(u32::from_be_bytes([
                    cursor[0], cursor[1], cursor[2], cursor[3],
                ]));
                cursor = &cursor[4..];
            }
            0x03 => {
                // Content Type (UTF-8 String)
                let (s, len) = read_string(cursor)?;
                props.content_type = Some(s);
                cursor = &cursor[len..];
            }
            0x08 => {
                // Response Topic (UTF-8 String)
                let (s, len) = read_string(cursor)?;
                props.response_topic = Some(s);
                cursor = &cursor[len..];
            }
            0x09 => {
                // Correlation Data (Binary data)
                let (b, len) = read_binary(cursor)?;
                props.correlation_data = Some(b);
                cursor = &cursor[len..];
            }
            0x11 => {
                // Session Expiry Interval (4-byte integer)
                if cursor.len() < 4 {
                    return Err(MqttError::MalformedPacket);
                }
                props.session_expiry_interval = Some(u32::from_be_bytes([
                    cursor[0], cursor[1], cursor[2], cursor[3],
                ]));
                cursor = &cursor[4..];
            }
            0x13 => {
                // Server Keep Alive (2-byte integer)
                let ka = read_u16(cursor)?;
                props.server_keep_alive = Some(ka);
                cursor = &cursor[2..];
            }
            0x26 => {
                // User Property (key-value pair of UTF-8 strings)
                let (_k, k_len) = read_string(cursor)?;
                cursor = &cursor[k_len..];
                let (_v, v_len) = read_string(cursor)?;
                cursor = &cursor[v_len..];
                props.user_properties_count += 1;
            }
            _ => {
                // Skip unknown or unhandled property gracefully
                break;
            }
        }
    }

    Ok((props, total_len))
}
