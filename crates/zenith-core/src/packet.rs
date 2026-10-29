//! Zero-copy MQTT packet definitions and parser.
//! Slices directly from network byte buffers with no heap allocations.

use crate::error::{MqttError, Result};
use crate::wire::{decode_varint, read_binary, read_string, read_u16};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Connect = 1,
    ConnAck = 2,
    Publish = 3,
    PubAck = 4,
    PubRec = 5,
    PubRel = 6,
    PubComp = 7,
    Subscribe = 8,
    SubAck = 9,
    Unsubscribe = 10,
    UnsubAck = 11,
    PingReq = 12,
    PingResp = 13,
    Disconnect = 14,
    Auth = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QoS {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl QoS {
    #[inline]
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(QoS::AtMostOnce),
            1 => Ok(QoS::AtLeastOnce),
            2 => Ok(QoS::ExactlyOnce),
            _ => Err(MqttError::MalformedPacket),
        }
    }
}

/// Zero-copy Connect Packet [MQTT-3.1.2]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect<'a> {
    pub protocol_name: &'a str,
    pub protocol_level: u8,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub client_id: &'a str,
    pub will: Option<Will<'a>>,
    pub username: Option<&'a str>,
    pub password: Option<&'a [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will<'a> {
    pub topic: &'a str,
    pub message: &'a [u8],
    pub qos: QoS,
    pub retain: bool,
}

/// Zero-copy Publish Packet [MQTT-3.3.1]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish<'a> {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    pub topic: &'a str,
    pub packet_id: Option<u16>,
    pub payload: &'a [u8],
}

/// Subscribed topic filter with requested QoS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscription<'a> {
    pub filter: &'a str,
    pub qos: QoS,
}

/// Zero-copy Subscribe Packet [MQTT-3.8.1]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe<'a> {
    pub packet_id: u16,
    pub subscriptions: &'a [u8], // raw slice to be parsed on-demand
}

/// Generic Packet ID carrier (PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketId {
    pub id: u16,
}

/// High-level Zero-Copy Packet representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet<'a> {
    Connect(Connect<'a>),
    ConnAck { session_present: bool, return_code: u8 },
    Publish(Publish<'a>),
    PubAck(PacketId),
    PubRec(PacketId),
    PubRel(PacketId),
    PubComp(PacketId),
    Subscribe(Subscribe<'a>),
    SubAck { packet_id: u16, return_codes: &'a [u8] },
    Unsubscribe { packet_id: u16, filters: &'a [u8] },
    UnsubAck(PacketId),
    PingReq,
    PingResp,
    Disconnect,
}

impl<'a> Packet<'a> {
    /// Zero-copy decode packet from slice.
    /// Returns `(Packet, total_packet_bytes_consumed)`.
    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(MqttError::IncompletePacket);
        }

        let first_byte = buf[0];
        let ptype_raw = first_byte >> 4;
        let flags = first_byte & 0x0F;

        let (rem_len, varint_len) = decode_varint(&buf[1..])?;
        let header_len = 1 + varint_len;
        let total_len = header_len + rem_len;

        if buf.len() < total_len {
            return Err(MqttError::IncompletePacket);
        }

        let payload_buf = &buf[header_len..total_len];

        match ptype_raw {
            1 => {
                // CONNECT
                let (proto_name, offset1) = read_string(payload_buf)?;
                let rest = &payload_buf[offset1..];
                if rest.is_empty() {
                    return Err(MqttError::IncompletePacket);
                }
                let proto_level = rest[0];
                let connect_flags = rest[1];
                let keep_alive = read_u16(&rest[2..4])?;
                let mut curr = &rest[4..];

                let (client_id, id_len) = read_string(curr)?;
                curr = &curr[id_len..];

                let clean_session = (connect_flags & 0x02) != 0;
                let will_flag = (connect_flags & 0x04) != 0;
                let will_qos = QoS::from_u8((connect_flags >> 3) & 0x03)?;
                let will_retain = (connect_flags & 0x20) != 0;
                let password_flag = (connect_flags & 0x40) != 0;
                let username_flag = (connect_flags & 0x80) != 0;

                let will = if will_flag {
                    let (w_topic, t_len) = read_string(curr)?;
                    curr = &curr[t_len..];
                    let (w_msg, m_len) = read_binary(curr)?;
                    curr = &curr[m_len..];
                    Some(Will {
                        topic: w_topic,
                        message: w_msg,
                        qos: will_qos,
                        retain: will_retain,
                    })
                } else {
                    None
                };

                let username = if username_flag {
                    let (uname, u_len) = read_string(curr)?;
                    curr = &curr[u_len..];
                    Some(uname)
                } else {
                    None
                };

                let password = if password_flag {
                    let (pwd, p_len) = read_binary(curr)?;
                    let _ = p_len;
                    Some(pwd)
                } else {
                    None
                };

                Ok((
                    Packet::Connect(Connect {
                        protocol_name: proto_name,
                        protocol_level: proto_level,
                        clean_session,
                        keep_alive,
                        client_id,
                        will,
                        username,
                        password,
                    }),
                    total_len,
                ))
            }
            3 => {
                // PUBLISH
                let dup = (flags & 0x08) != 0;
                let qos = QoS::from_u8((flags >> 1) & 0x03)?;
                let retain = (flags & 0x01) != 0;

                let (topic, topic_len) = read_string(payload_buf)?;
                let mut offset = topic_len;

                let packet_id = if qos != QoS::AtMostOnce {
                    let pid = read_u16(&payload_buf[offset..])?;
                    offset += 2;
                    Some(pid)
                } else {
                    None
                };

                let payload = &payload_buf[offset..];
                Ok((
                    Packet::Publish(Publish {
                        dup,
                        qos,
                        retain,
                        topic,
                        packet_id,
                        payload,
                    }),
                    total_len,
                ))
            }
            4 => {
                // PUBACK
                let id = read_u16(payload_buf)?;
                Ok((Packet::PubAck(PacketId { id }), total_len))
            }
            5 => {
                // PUBREC
                let id = read_u16(payload_buf)?;
                Ok((Packet::PubRec(PacketId { id }), total_len))
            }
            6 => {
                // PUBREL
                let id = read_u16(payload_buf)?;
                Ok((Packet::PubRel(PacketId { id }), total_len))
            }
            7 => {
                // PUBCOMP
                let id = read_u16(payload_buf)?;
                Ok((Packet::PubComp(PacketId { id }), total_len))
            }
            8 => {
                // SUBSCRIBE
                let packet_id = read_u16(payload_buf)?;
                let subscriptions = &payload_buf[2..];
                Ok((
                    Packet::Subscribe(Subscribe {
                        packet_id,
                        subscriptions,
                    }),
                    total_len,
                ))
            }
            10 => {
                // UNSUBSCRIBE
                let packet_id = read_u16(payload_buf)?;
                let filters = &payload_buf[2..];
                Ok((Packet::Unsubscribe { packet_id, filters }, total_len))
            }
            12 => Ok((Packet::PingReq, total_len)),
            13 => Ok((Packet::PingResp, total_len)),
            14 => Ok((Packet::Disconnect, total_len)),
            _ => Err(MqttError::MalformedPacket),
        }
    }

    /// Serializes fixed responses into preallocated output buffers without heap allocation.
    #[inline]
    pub fn encode_connack(session_present: bool, return_code: u8, out: &mut [u8]) -> Result<usize> {
        if out.len() < 4 {
            return Err(MqttError::BufferTooSmall);
        }
        out[0] = 0x20; // CONNACK packet type
        out[1] = 0x02; // Remaining length
        out[2] = if session_present { 1 } else { 0 };
        out[3] = return_code;
        Ok(4)
    }

    #[inline]
    pub fn encode_puback(packet_id: u16, out: &mut [u8]) -> Result<usize> {
        if out.len() < 4 {
            return Err(MqttError::BufferTooSmall);
        }
        out[0] = 0x40; // PUBACK packet type
        out[1] = 0x02; // Remaining length
        let bytes = packet_id.to_be_bytes();
        out[2] = bytes[0];
        out[3] = bytes[1];
        Ok(4)
    }

    #[inline]
    pub fn encode_pingresp(out: &mut [u8]) -> Result<usize> {
        if out.len() < 2 {
            return Err(MqttError::BufferTooSmall);
        }
        out[0] = 0xD0; // PINGRESP
        out[1] = 0x00;
        Ok(2)
    }
}
