#[cfg(test)]
mod tests {
    use zenith_broker::route::BrokerEngine;
    use zenith_broker::session::InFlightState;
    use zenith_core::packet::{Connect, Publish, QoS};

    fn make_test_conn<'a>(client_id: &'a str, clean_session: bool) -> Connect<'a> {
        Connect {
            protocol_name: "MQTT",
            protocol_level: 4,
            clean_session,
            keep_alive: 60,
            client_id,
            will: None,
            username: None,
            password: None,
        }
    }

    #[test]
    fn test_qos1_handshake_flow() {
        let mut broker = BrokerEngine::new();
        broker.handle_connect(&make_test_conn("subscriber_1", false)).unwrap();
        broker.handle_subscribe("subscriber_1", "alerts/+", 1);

        let pub_msg = Publish {
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            topic: "alerts/fire",
            packet_id: Some(100),
            payload: b"EVACUATE",
        };

        let dispatches = broker.handle_publish(None, &pub_msg);
        assert_eq!(dispatches.len(), 1);
        let (cid, msg_opt) = &dispatches[0];
        assert_eq!(cid, "subscriber_1");
        let msg = msg_opt.as_ref().unwrap();
        assert_eq!(msg.qos, QoS::AtLeastOnce);
        assert_eq!(msg.packet_id, 1);
        assert_eq!(msg.state, InFlightState::WaitingPubAck);

        // Acknowledge with PUBACK
        let acked = broker.handle_puback("subscriber_1", 1);
        assert!(acked);

        // Subsequent duplicate PUBACK returns false
        assert!(!broker.handle_puback("subscriber_1", 1));
    }

    #[test]
    fn test_qos2_four_step_handshake() {
        let mut broker = BrokerEngine::new();
        broker.handle_connect(&make_test_conn("sub_qos2", false)).unwrap();
        broker.handle_subscribe("sub_qos2", "orders/#", 2);

        let pub_msg = Publish {
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: false,
            topic: "orders/create",
            packet_id: Some(200),
            payload: b"order_id_42",
        };

        let dispatches = broker.handle_publish(None, &pub_msg);
        let (_, msg_opt) = &dispatches[0];
        let msg = msg_opt.as_ref().unwrap();
        assert_eq!(msg.qos, QoS::ExactlyOnce);
        let pid = msg.packet_id;
        assert_eq!(msg.state, InFlightState::WaitingPubRec);

        // Step 2: Client responds with PUBREC -> Broker transitions to WaitingPubComp
        assert!(broker.handle_pubrec("sub_qos2", pid));

        // Step 4: Client receives PUBREL and replies with PUBCOMP -> Broker completes & cleans up
        assert!(broker.handle_pubcomp("sub_qos2", pid));

        // Attempting to PUBCOMP again fails
        assert!(!broker.handle_pubcomp("sub_qos2", pid));
    }

    #[test]
    fn test_offline_message_queue_and_replay() {
        let mut broker = BrokerEngine::new();
        // Step 1: Connect persistent client
        broker.handle_connect(&make_test_conn("edge_device", false)).unwrap();
        broker.handle_subscribe("edge_device", "firmware/update", 1);

        // Step 2: Edge device goes offline (clean disconnect)
        broker.handle_clean_disconnect("edge_device");

        // Step 3: Publish message while device is offline
        let pub_msg = Publish {
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            topic: "firmware/update",
            packet_id: Some(5),
            payload: b"v2.0.0",
        };
        let dispatches = broker.handle_publish(None, &pub_msg);
        assert_eq!(dispatches.len(), 1);
        assert!(dispatches[0].1.is_none());

        // Step 4: Device reconnects with clean_session = false
        let (session_present, replayed) = broker.handle_connect(&make_test_conn("edge_device", false)).unwrap();
        assert!(session_present);
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].topic, "firmware/update");
        assert_eq!(replayed[0].payload, b"v2.0.0");
        assert_eq!(replayed[0].qos, QoS::AtLeastOnce);
    }
}
