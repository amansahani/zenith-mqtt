//! Core broker routing engine, ACL security, and Last Will & Testament (LWT).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use zenith_core::packet::{Connect, Publish, QoS};
use zenith_trie::trie::{SubEntry, TopicTrie};

use crate::security::SecurityManager;
use crate::session::{InFlightMessage, SessionState, StoredWill};

/// In-memory broker engine
pub struct BrokerEngine {
    /// Topic subscription trie indexed by client identifier
    trie: TopicTrie<String>,
    /// Full session states indexed by client identifier
    sessions: BTreeMap<String, SessionState>,
    /// Retained messages by topic
    retained: BTreeMap<String, InFlightMessage>,
    /// Authentication and topic ACL security manager
    pub security: SecurityManager,
}

impl Default for BrokerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerEngine {
    pub fn new() -> Self {
        Self {
            trie: TopicTrie::new(),
            sessions: BTreeMap::new(),
            retained: BTreeMap::new(),
            security: SecurityManager::default(),
        }
    }

    /// Process a CONNECT packet [MQTT-3.1].
    /// Returns `Result<(session_present, offline_messages_to_replay), return_code>`.
    pub fn handle_connect(
        &mut self,
        conn: &Connect<'_>,
    ) -> Result<(bool, Vec<InFlightMessage>), u8> {
        // Authenticate credentials [MQTT-3.1.2.8]
        if !self.security.authenticate(conn.username, conn.password) {
            return Err(0x05); // Connection Refused: not authorized
        }

        let client_id = conn.client_id;
        let mut offline_messages = Vec::new();

        let will = conn.will.as_ref().map(|w| StoredWill {
            topic: String::from(w.topic),
            message: w.message.to_vec(),
            qos: w.qos,
            retain: w.retain,
        });

        let session_present = if conn.clean_session {
            self.sessions.remove(client_id);
            self.sessions.insert(
                String::from(client_id),
                SessionState::new(
                    client_id,
                    conn.clean_session,
                    conn.keep_alive,
                    will,
                    conn.username.map(String::from),
                ),
            );
            false
        } else if let Some(session) = self.sessions.get_mut(client_id) {
            session.connected = true;
            session.keep_alive = conn.keep_alive;
            session.will = will;
            // Drain offline queue to replay
            while let Some(mut msg) = session.offline_queue.pop_front() {
                if let Ok(pid) = session.allocate_packet_id() {
                    msg.packet_id = pid;
                    session.outbound_inflight.insert(pid, msg.clone());
                    offline_messages.push(msg);
                } else {
                    session.offline_queue.push_front(msg);
                    break;
                }
            }
            true
        } else {
            self.sessions.insert(
                String::from(client_id),
                SessionState::new(
                    client_id,
                    conn.clean_session,
                    conn.keep_alive,
                    will,
                    conn.username.map(String::from),
                ),
            );
            false
        };

        Ok((session_present, offline_messages))
    }

    /// Process a SUBSCRIBE topic filter [MQTT-3.8] with ACL check.
    pub fn handle_subscribe(
        &mut self,
        client_id: &str,
        filter: &str,
        qos: u8,
    ) -> Option<Vec<InFlightMessage>> {
        let username = self.sessions.get(client_id).and_then(|s| s.username.as_deref());
        if !self.security.can_subscribe(username, filter) {
            return None; // Unauthorized subscription
        }

        self.trie.subscribe(filter, String::from(client_id), qos);

        // Deliver matching retained messages [MQTT-3.3.1.3]
        let mut matching_retained = Vec::new();
        for (topic, msg) in &self.retained {
            let single_match = self.trie.match_topic(topic);
            if single_match.iter().any(|s| s.client_id == client_id) {
                matching_retained.push(msg.clone());
            }
        }
        Some(matching_retained)
    }

    /// Process an UNSUBSCRIBE topic filter [MQTT-3.10].
    pub fn handle_unsubscribe(&mut self, client_id: &str, filter: &str) {
        self.trie.unsubscribe(filter, &String::from(client_id));
    }

    /// Process an incoming PUBLISH packet [MQTT-3.3] with ACL check.
    pub fn handle_publish(
        &mut self,
        client_id: Option<&str>,
        packet: &Publish<'_>,
    ) -> Vec<(String, Option<InFlightMessage>)> {
        let username = client_id.and_then(|cid| self.sessions.get(cid).and_then(|s| s.username.as_deref()));
        if !self.security.can_publish(username, packet.topic) {
            return Vec::new(); // Drop unauthorized publish
        }

        let subscribers: Vec<SubEntry<String>> = self.trie.match_topic(packet.topic);

        if packet.retain {
            if packet.payload.is_empty() {
                self.retained.remove(packet.topic);
            } else {
                self.retained.insert(
                    String::from(packet.topic),
                    InFlightMessage {
                        packet_id: 0,
                        topic: String::from(packet.topic),
                        payload: packet.payload.to_vec(),
                        qos: packet.qos,
                        state: crate::session::InFlightState::WaitingPubAck,
                    },
                );
            }
        }

        let mut dispatches = Vec::with_capacity(subscribers.len());
        for sub in subscribers {
            let sub_qos = match sub.qos {
                0 => QoS::AtMostOnce,
                1 => match packet.qos {
                    QoS::AtMostOnce => QoS::AtMostOnce,
                    _ => QoS::AtLeastOnce,
                },
                _ => packet.qos,
            };

            if let Some(session) = self.sessions.get_mut(&sub.client_id) {
                if let Ok(msg_opt) = session.enqueue_outbound(packet.topic, packet.payload, sub_qos) {
                    dispatches.push((sub.client_id.clone(), msg_opt));
                }
            }
        }

        dispatches
    }

    /// Client closes connection cleanly via DISCONNECT packet [MQTT-3.14].
    /// In a clean disconnect, the Will message is NOT published [MQTT-3.14.4-3].
    pub fn handle_clean_disconnect(&mut self, client_id: &str) {
        if let Some(session) = self.sessions.get_mut(client_id) {
            session.connected = false;
            session.will = None; // Invalidate Will
            if session.clean_session {
                self.sessions.remove(client_id);
            }
        }
    }

    /// Abnormal disconnect (socket error, EOF, or keep-alive timeout).
    /// Fires the client's Last Will and Testament if present [MQTT-3.1.2.5].
    pub fn handle_abnormal_disconnect(
        &mut self,
        client_id: &str,
    ) -> Vec<(String, Option<InFlightMessage>)> {
        let will_msg = if let Some(session) = self.sessions.get_mut(client_id) {
            session.connected = false;
            let w = session.will.take();
            if session.clean_session {
                self.sessions.remove(client_id);
            }
            w
        } else {
            None
        };

        if let Some(will) = will_msg {
            let pub_pkt = Publish {
                dup: false,
                qos: will.qos,
                retain: will.retain,
                topic: &will.topic,
                packet_id: None,
                payload: &will.message,
            };
            self.handle_publish(None, &pub_pkt)
        } else {
            Vec::new()
        }
    }

    pub fn handle_puback(&mut self, client_id: &str, packet_id: u16) -> bool {
        if let Some(session) = self.sessions.get_mut(client_id) {
            session.handle_puback(packet_id)
        } else {
            false
        }
    }

    pub fn handle_pubrec(&mut self, client_id: &str, packet_id: u16) -> bool {
        if let Some(session) = self.sessions.get_mut(client_id) {
            session.handle_pubrec(packet_id)
        } else {
            false
        }
    }

    pub fn handle_pubcomp(&mut self, client_id: &str, packet_id: u16) -> bool {
        if let Some(session) = self.sessions.get_mut(client_id) {
            session.handle_pubcomp(packet_id)
        } else {
            false
        }
    }
}
