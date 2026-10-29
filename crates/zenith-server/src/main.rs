//! Multi-threaded, high-throughput Zenith MQTT Server.
//! Supports MQTT 3.1.1 & 5.0, Last Will & Testament, and Keep-Alive timeouts.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use zenith_broker::route::BrokerEngine;
use zenith_broker::session::InFlightMessage;
use zenith_core::packet::{Packet, QoS};

type ClientWriters = Arc<Mutex<HashMap<String, TcpStream>>>;

fn main() {
    let bind_addr = "127.0.0.1:1883";
    let listener = TcpListener::bind(bind_addr).expect("Failed to bind TCP listener to 1883");
    println!("Zenith MQTT Server listening on {}", bind_addr);

    let broker = Arc::new(Mutex::new(BrokerEngine::new()));
    let writers: ClientWriters = Arc::new(Mutex::new(HashMap::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let broker_clone = Arc::clone(&broker);
                let writers_clone = Arc::clone(&writers);
                thread::spawn(move || {
                    handle_client(stream, broker_clone, writers_clone);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    broker: Arc<Mutex<BrokerEngine>>,
    writers: ClientWriters,
) {
    let mut buffer = [0u8; 8192];
    let mut client_id = String::new();
    let mut clean_disconnect = false;
    let mut keep_alive_dur = Duration::from_secs(60);

    // Set non-blocking with timeout for keep-alive detection
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut last_activity = Instant::now();

    loop {
        // Enforce Keep-Alive timeout [MQTT-3.1.2.10]: 1.5 * KeepAlive
        if !client_id.is_empty() && last_activity.elapsed() > keep_alive_dur + (keep_alive_dur / 2) {
            eprintln!("Client {} timed out (Keep-Alive exceeded)", client_id);
            break;
        }

        let bytes_read = match stream.read(&mut buffer) {
            Ok(0) => break, // EOF
            Ok(n) => {
                last_activity = Instant::now();
                n
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(_) => break, // Socket error
        };

        let mut slice = &buffer[..bytes_read];

        while !slice.is_empty() {
            let (packet, consumed) = match Packet::decode(slice) {
                Ok(res) => res,
                Err(_) => break,
            };

            slice = &slice[consumed..];

            match packet {
                Packet::Connect(ref conn) => {
                    client_id = conn.client_id.to_string();
                    if conn.keep_alive > 0 {
                        keep_alive_dur = Duration::from_secs(conn.keep_alive as u64);
                    }

                    let connect_result = {
                        let mut b = broker.lock().unwrap();
                        b.handle_connect(conn)
                    };

                    match connect_result {
                        Ok((session_present, offline_messages)) => {
                            if let Ok(cloned_stream) = stream.try_clone() {
                                let mut w = writers.lock().unwrap();
                                w.insert(client_id.clone(), cloned_stream);
                            }

                            let mut resp = [0u8; 4];
                            if let Ok(len) = Packet::encode_connack(session_present, 0, &mut resp) {
                                let _ = stream.write_all(&resp[..len]);
                            }

                            for msg in offline_messages {
                                deliver_publish(&mut stream, &msg.topic, &msg.payload, msg.qos, false, Some(msg.packet_id));
                            }
                        }
                        Err(code) => {
                            let mut resp = [0u8; 4];
                            let _ = Packet::encode_connack(false, code, &mut resp);
                            let _ = stream.write_all(&resp);
                            return;
                        }
                    }
                }
                Packet::Subscribe(sub) => {
                    if sub.subscriptions.len() >= 3 {
                        let len = u16::from_be_bytes([sub.subscriptions[0], sub.subscriptions[1]]) as usize;
                        if sub.subscriptions.len() >= 2 + len + 1 {
                            if let Ok(filter) = core::str::from_utf8(&sub.subscriptions[2..2 + len]) {
                                let requested_qos = sub.subscriptions[2 + len];
                                let retained_opt = {
                                    let mut b = broker.lock().unwrap();
                                    b.handle_subscribe(&client_id, filter, requested_qos)
                                };

                                if let Some(retained) = retained_opt {
                                    let suback = [
                                        0x90, 0x03,
                                        (sub.packet_id >> 8) as u8,
                                        (sub.packet_id & 0xFF) as u8,
                                        requested_qos,
                                    ];
                                    let _ = stream.write_all(&suback);

                                    for msg in retained {
                                        deliver_publish(&mut stream, &msg.topic, &msg.payload, msg.qos, true, None);
                                    }
                                } else {
                                    // Subscription rejected by ACL (return code 0x80)
                                    let suback = [
                                        0x90, 0x03,
                                        (sub.packet_id >> 8) as u8,
                                        (sub.packet_id & 0xFF) as u8,
                                        0x80,
                                    ];
                                    let _ = stream.write_all(&suback);
                                }
                            }
                        }
                    }
                }
                Packet::Publish(ref pub_msg) => {
                    let dispatches = {
                        let mut b = broker.lock().unwrap();
                        b.handle_publish(Some(&client_id), pub_msg)
                    };

                    if pub_msg.qos == QoS::AtLeastOnce {
                        if let Some(pid) = pub_msg.packet_id {
                            let mut ack = [0u8; 4];
                            if let Ok(len) = Packet::encode_puback(pid, &mut ack) {
                                let _ = stream.write_all(&ack[..len]);
                            }
                        }
                    }

                    broadcast_dispatches(&writers, dispatches);
                }
                Packet::PubAck(ack) => {
                    let mut b = broker.lock().unwrap();
                    b.handle_puback(&client_id, ack.id);
                }
                Packet::PubRec(rec) => {
                    let mut b = broker.lock().unwrap();
                    if b.handle_pubrec(&client_id, rec.id) {
                        let rel = [0x62, 0x02, (rec.id >> 8) as u8, (rec.id & 0xFF) as u8];
                        let _ = stream.write_all(&rel);
                    }
                }
                Packet::PubComp(comp) => {
                    let mut b = broker.lock().unwrap();
                    b.handle_pubcomp(&client_id, comp.id);
                }
                Packet::PingReq => {
                    let mut resp = [0u8; 2];
                    if let Ok(len) = Packet::encode_pingresp(&mut resp) {
                        let _ = stream.write_all(&resp[..len]);
                    }
                }
                Packet::Disconnect => {
                    clean_disconnect = true;
                    break;
                }
                _ => {}
            }
        }
    }

    // Teardown socket & dispatch LWT if abnormal
    if !client_id.is_empty() {
        {
            let mut w = writers.lock().unwrap();
            w.remove(&client_id);
        }

        let lwt_dispatches = {
            let mut b = broker.lock().unwrap();
            if clean_disconnect {
                b.handle_clean_disconnect(&client_id);
                Vec::new()
            } else {
                b.handle_abnormal_disconnect(&client_id)
            }
        };

        broadcast_dispatches(&writers, lwt_dispatches);
    }
}

fn broadcast_dispatches(
    writers: &ClientWriters,
    dispatches: Vec<(String, Option<InFlightMessage>)>,
) {
    let mut w = writers.lock().unwrap();
    for (target_id, msg_opt) in dispatches {
        if let Some(msg) = msg_opt {
            if let Some(target_stream) = w.get_mut(&target_id) {
                deliver_publish(
                    target_stream,
                    &msg.topic,
                    &msg.payload,
                    msg.qos,
                    false,
                    if msg.qos != QoS::AtMostOnce { Some(msg.packet_id) } else { None },
                );
            }
        }
    }
}

fn deliver_publish(
    stream: &mut TcpStream,
    topic: &str,
    payload: &[u8],
    qos: QoS,
    retain: bool,
    packet_id: Option<u16>,
) {
    let topic_bytes = topic.as_bytes();
    let id_len = if qos != QoS::AtMostOnce { 2 } else { 0 };
    let rem_len = 2 + topic_bytes.len() + id_len + payload.len();

    let qos_flag = match qos {
        QoS::AtMostOnce => 0x00,
        QoS::AtLeastOnce => 0x02,
        QoS::ExactlyOnce => 0x04,
    };
    let first_byte = 0x30 | qos_flag | if retain { 0x01 } else { 0x00 };
    let mut varint_buf = [0u8; 4];
    if let Ok(vlen) = zenith_core::wire::encode_varint(rem_len, &mut varint_buf) {
        let _ = stream.write_all(&[first_byte]);
        let _ = stream.write_all(&varint_buf[..vlen]);
        let tlen = (topic_bytes.len() as u16).to_be_bytes();
        let _ = stream.write_all(&tlen);
        let _ = stream.write_all(topic_bytes);
        if let Some(pid) = packet_id {
            let pid_bytes = pid.to_be_bytes();
            let _ = stream.write_all(&pid_bytes);
        }
        let _ = stream.write_all(payload);
    }
}
