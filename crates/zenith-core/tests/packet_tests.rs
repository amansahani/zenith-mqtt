#[cfg(test)]
mod tests {
    use zenith_core::packet::{Packet, QoS};
    use zenith_core::wire::{decode_varint, encode_varint};

    #[test]
    fn test_varint_encode_decode() {
        let test_cases = [0, 127, 128, 16383, 16384, 2097151, 268435455];
        let mut buf = [0u8; 4];

        for &val in &test_cases {
            let encoded_len = encode_varint(val, &mut buf).unwrap();
            let (decoded_val, consumed) = decode_varint(&buf[..encoded_len]).unwrap();
            assert_eq!(val, decoded_val);
            assert_eq!(encoded_len, consumed);
        }
    }

    #[test]
    fn test_decode_pingreq() {
        let raw = [0xC0, 0x00];
        let (packet, consumed) = Packet::decode(&raw).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(packet, Packet::PingReq);
    }

    #[test]
    fn test_decode_publish_qos0() {
        // Topic: "a/b", Payload: "hello"
        let raw = [
            0x30, 0x0A, // PUBLISH, rem_len = 10
            0x00, 0x03, b'a', b'/', b'b', // Topic "a/b"
            b'h', b'e', b'l', b'l', b'o', // Payload
        ];
        let (packet, consumed) = Packet::decode(&raw).unwrap();
        assert_eq!(consumed, 12);
        if let Packet::Publish(p) = packet {
            assert_eq!(p.topic, "a/b");
            assert_eq!(p.payload, b"hello");
            assert_eq!(p.qos, QoS::AtMostOnce);
            assert_eq!(p.retain, false);
            assert_eq!(p.packet_id, None);
        } else {
            panic!("Expected Publish packet");
        }
    }

    #[test]
    fn test_encode_connack() {
        let mut buf = [0u8; 10];
        let written = Packet::encode_connack(false, 0, &mut buf).unwrap();
        assert_eq!(written, 4);
        assert_eq!(&buf[..4], &[0x20, 0x02, 0x00, 0x00]);
    }
}
