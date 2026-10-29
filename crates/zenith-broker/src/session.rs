//! QoS 1 and QoS 2 Handshake state machines conforming to [MQTT-4.3.2] and [MQTT-4.3.3].
//! Implements bounded in-flight tracking with anti-OOM ring buffers and offline session queues.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use zenith_core::error::{MqttError, Result};
use zenith_core::packet::QoS;

/// Last Will and Testament configuration [MQTT-3.1.2.5]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWill {
    pub topic: String,
    pub message: Vec<u8>,
    pub qos: QoS,
    pub retain: bool,
}

/// Represents an in-flight outbound packet awaiting acknowledgment from a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightMessage {
    pub packet_id: u16,
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: QoS,
    pub state: InFlightState,
}

/// Handshake progress states for QoS 1 and QoS 2 flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlightState {
    /// QoS 1: Published, waiting for PUBACK [MQTT-4.3.2]
    WaitingPubAck,
    /// QoS 2: Published, waiting for PUBREC [MQTT-4.3.3-1]
    WaitingPubRec,
    /// QoS 2: Received PUBREC, sent PUBREL, waiting for PUBCOMP [MQTT-4.3.3-2]
    WaitingPubComp,
}

/// State tracking for an inbound QoS 2 publish from a client awaiting completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundQoS2State {
    /// Received PUBLISH, sent PUBREC, awaiting PUBREL from publisher
    WaitingPubRel,
}

/// Persistent or ephemeral client session tracking offline queues, LWT, and in-flight handshakes.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub client_id: String,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub connected: bool,
    pub will: Option<StoredWill>,
    pub username: Option<String>,
    /// Next Packet ID for outbound messages (1 to 65535, 0 is forbidden per [MQTT-2.3.1-1])
    next_packet_id: u16,
    /// Bounded in-flight outbound messages pending ACK
    pub outbound_inflight: BTreeMap<u16, InFlightMessage>,
    /// Bounded in-flight inbound QoS 2 state to prevent duplicate delivery [MQTT-4.3.3]
    pub inbound_qos2_received: BTreeMap<u16, InboundQoS2State>,
    /// Bounded offline message queue (for clean_session = false clients)
    pub offline_queue: VecDeque<InFlightMessage>,
    /// Maximum allowed in-flight messages (anti-slowloris / HoL guard)
    pub max_inflight: usize,
    /// Maximum allowed queued offline messages (anti-OOM protection)
    pub max_offline_queue: usize,
}

impl SessionState {
    pub fn new(
        client_id: &str,
        clean_session: bool,
        keep_alive: u16,
        will: Option<StoredWill>,
        username: Option<String>,
    ) -> Self {
        Self {
            client_id: String::from(client_id),
            clean_session,
            keep_alive,
            connected: true,
            will,
            username,
            next_packet_id: 1,
            outbound_inflight: BTreeMap::new(),
            inbound_qos2_received: BTreeMap::new(),
            offline_queue: VecDeque::new(),
            max_inflight: 64,          // Safe default; configurable
            max_offline_queue: 1000,    // Hard memory bound; drops oldest or rejects
        }
    }

    /// Allocates the next sequential non-zero 16-bit Packet ID [MQTT-2.3.1-1].
    pub fn allocate_packet_id(&mut self) -> Result<u16> {
        if self.outbound_inflight.len() >= self.max_inflight {
            return Err(MqttError::BufferTooSmall);
        }

        let start = self.next_packet_id;
        loop {
            let candidate = self.next_packet_id;
            if self.next_packet_id == u16::MAX {
                self.next_packet_id = 1;
            } else {
                self.next_packet_id += 1;
            }

            if !self.outbound_inflight.contains_key(&candidate) {
                return Ok(candidate);
            }

            if self.next_packet_id == start {
                return Err(MqttError::BufferTooSmall);
            }
        }
    }

    /// Enqueues a message for delivery.
    pub fn enqueue_outbound(
        &mut self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
    ) -> Result<Option<InFlightMessage>> {
        if qos == QoS::AtMostOnce {
            // QoS 0 has no handshake; immediate delivery
            return Ok(Some(InFlightMessage {
                packet_id: 0,
                topic: String::from(topic),
                payload: payload.to_vec(),
                qos,
                state: InFlightState::WaitingPubAck,
            }));
        }

        if !self.connected {
            if !self.clean_session {
                // Queue for reconnect
                if self.offline_queue.len() >= self.max_offline_queue {
                    self.offline_queue.pop_front();
                }
                self.offline_queue.push_back(InFlightMessage {
                    packet_id: 0,
                    topic: String::from(topic),
                    payload: payload.to_vec(),
                    qos,
                    state: match qos {
                        QoS::AtLeastOnce => InFlightState::WaitingPubAck,
                        QoS::ExactlyOnce => InFlightState::WaitingPubRec,
                        QoS::AtMostOnce => unreachable!(),
                    },
                });
            }
            return Ok(None);
        }

        let pid = match self.allocate_packet_id() {
            Ok(id) => id,
            Err(_) => {
                if self.offline_queue.len() < self.max_offline_queue {
                    self.offline_queue.push_back(InFlightMessage {
                        packet_id: 0,
                        topic: String::from(topic),
                        payload: payload.to_vec(),
                        qos,
                        state: match qos {
                            QoS::AtLeastOnce => InFlightState::WaitingPubAck,
                            QoS::ExactlyOnce => InFlightState::WaitingPubRec,
                            QoS::AtMostOnce => unreachable!(),
                        },
                    });
                }
                return Ok(None);
            }
        };

        let initial_state = match qos {
            QoS::AtLeastOnce => InFlightState::WaitingPubAck,
            QoS::ExactlyOnce => InFlightState::WaitingPubRec,
            QoS::AtMostOnce => unreachable!(),
        };

        let msg = InFlightMessage {
            packet_id: pid,
            topic: String::from(topic),
            payload: payload.to_vec(),
            qos,
            state: initial_state,
        };

        self.outbound_inflight.insert(pid, msg.clone());
        Ok(Some(msg))
    }

    /// Handles incoming PUBACK from subscriber [MQTT-4.3.2]
    pub fn handle_puback(&mut self, packet_id: u16) -> bool {
        if let Some(msg) = self.outbound_inflight.get(&packet_id) {
            if msg.qos == QoS::AtLeastOnce && msg.state == InFlightState::WaitingPubAck {
                self.outbound_inflight.remove(&packet_id);
                return true;
            }
        }
        false
    }

    /// Handles incoming PUBREC from subscriber (QoS 2 Step 2) [MQTT-4.3.3-1]
    pub fn handle_pubrec(&mut self, packet_id: u16) -> bool {
        if let Some(msg) = self.outbound_inflight.get_mut(&packet_id) {
            if msg.qos == QoS::ExactlyOnce && msg.state == InFlightState::WaitingPubRec {
                msg.state = InFlightState::WaitingPubComp;
                return true;
            }
        }
        false
    }

    /// Handles incoming PUBCOMP from subscriber (QoS 2 Step 4) [MQTT-4.3.3-2]
    pub fn handle_pubcomp(&mut self, packet_id: u16) -> bool {
        if let Some(msg) = self.outbound_inflight.get(&packet_id) {
            if msg.qos == QoS::ExactlyOnce && msg.state == InFlightState::WaitingPubComp {
                self.outbound_inflight.remove(&packet_id);
                return true;
            }
        }
        false
    }

    /// Inbound QoS 2 check
    pub fn handle_inbound_qos2_publish(&mut self, packet_id: u16) -> bool {
        if self.inbound_qos2_received.contains_key(&packet_id) {
            return false;
        }
        self.inbound_qos2_received.insert(packet_id, InboundQoS2State::WaitingPubRel);
        true
    }

    /// Inbound QoS 2 PUBREL release
    pub fn handle_inbound_pubrel(&mut self, packet_id: u16) -> bool {
        self.inbound_qos2_received.remove(&packet_id).is_some()
    }
}
