#[cfg(test)]
mod tests {
    use zenith_broker::route::BrokerEngine;
    use zenith_broker::security::Permission;
    use zenith_core::packet::{Connect, Publish, QoS, Will};

    #[test]
    fn test_last_will_and_testament_on_abnormal_disconnect() {
        let mut broker = BrokerEngine::new();
        // Client 1 (Monitor) connects and subscribes to death alerts
        let conn_mon = Connect {
            protocol_name: "MQTT",
            protocol_level: 4,
            clean_session: true,
            keep_alive: 60,
            client_id: "monitor_app",
            will: None,
            username: None,
            password: None,
        };
        broker.handle_connect(&conn_mon).unwrap();
        broker.handle_subscribe("monitor_app", "status/devices/+", 1);

        // Client 2 (IoT Sensor) connects with LWT
        let will = Will {
            topic: "status/devices/sensor1",
            message: b"OFFLINE_UNEXPECTED",
            qos: QoS::AtLeastOnce,
            retain: false,
        };
        let conn_sensor = Connect {
            protocol_name: "MQTT",
            protocol_level: 4,
            clean_session: true,
            keep_alive: 30,
            client_id: "sensor1",
            will: Some(will),
            username: None,
            password: None,
        };
        broker.handle_connect(&conn_sensor).unwrap();

        // Simulate abnormal disconnect (e.g. power lost / socket drop)
        let dispatches = broker.handle_abnormal_disconnect("sensor1");
        assert_eq!(dispatches.len(), 1);
        let (cid, msg_opt) = &dispatches[0];
        assert_eq!(cid, "monitor_app");
        let msg = msg_opt.as_ref().unwrap();
        assert_eq!(msg.topic, "status/devices/sensor1");
        assert_eq!(msg.payload, b"OFFLINE_UNEXPECTED");
    }

    #[test]
    fn test_authentication_and_topic_acl() {
        let mut broker = BrokerEngine::new();
        broker.security.allow_anonymous = false;
        broker.security.add_user("alice", "secret123");
        broker.security.add_acl("alice", "home/livingroom/+", Permission::ReadWrite);

        // 1. Wrong password rejected
        let conn_bad = Connect {
            protocol_name: "MQTT",
            protocol_level: 4,
            clean_session: true,
            keep_alive: 60,
            client_id: "bad_actor",
            will: None,
            username: Some("alice"),
            password: Some(b"wrongpass"),
        };
        assert!(broker.handle_connect(&conn_bad).is_err());

        // 2. Good password accepted
        let conn_good = Connect {
            protocol_name: "MQTT",
            protocol_level: 4,
            clean_session: true,
            keep_alive: 60,
            client_id: "alice_phone",
            will: None,
            username: Some("alice"),
            password: Some(b"secret123"),
        };
        assert!(broker.handle_connect(&conn_good).is_ok());

        // 3. Authorized subscription
        let sub_ok = broker.handle_subscribe("alice_phone", "home/livingroom/temp", 1);
        assert!(sub_ok.is_some());

        // 4. Authorized publish
        let pub_ok = Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: "home/livingroom/temp",
            packet_id: None,
            payload: b"21.0C",
        };
        let dispatches = broker.handle_publish(Some("alice_phone"), &pub_ok);
        assert_eq!(dispatches.len(), 1);
    }
}
