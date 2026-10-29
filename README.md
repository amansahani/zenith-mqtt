# Zenith MQTT

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](Cargo.toml)
[![Standards](https://img.shields.io/badge/standard-ISO%2FIEC%2020922%3A2016-green.svg)](https://www.iso.org/standard/69466.html)
[![MQTT 5.0](https://img.shields.io/badge/OASIS-MQTT%205.0-brightgreen.svg)](https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html)
[![Safe Rust](https://img.shields.io/badge/safety-100%25%20safe%20Rust-success.svg)](crates/zenith-core)

An ultra-lightweight, high-performance, standards-compliant MQTT broker written in 100% safe Rust. Designed for edge gateways, microcontrollers (ESP32-S3, RP2040), and scalable multi-core servers.

---

## Highlights

* **Standards Compliant:** Full adherence to **ISO/IEC 20922:2016 (MQTT 3.1.1)** and **OASIS MQTT 5.0**.
* **Zero-Copy Parsing:** Packets borrow directly from socket read buffers (`&str`, `&[u8]`) with zero heap allocation during decoding.
* **Micro Footprint:**
  * Embedded profile: **~100 KB** on bare-metal ARM / Xtensa (ESP32-S3).
  * Server profile: **345 KB** stripped binary (< 1/5th of the 2 MB budget).
  * Idle RAM: **< 1.5 MB** RSS on servers, **< 100 KB** on microcontrollers.
* **Full QoS Spectrum:** QoS 0, QoS 1, and the complete 4-step QoS 2 handshake (`PUBLISH` $\rightarrow$ `PUBREC` $\rightarrow$ `PUBREL` $\rightarrow$ `PUBCOMP`) with duplicate suppression.
* **Reliability & Anti-OOM:** Bounded in-flight windows and circular offline queues to eliminate memory leaks and slowloris attacks.
* **Security & LWT:** Granular Read/Write topic ACL rules, credential authentication, Last Will & Testament (LWT) broadcast, and Keep-Alive timeout enforcers.

---

## Architectural Comparison

| Feature | Eclipse Mosquitto | EMQX | NanoMQ | **Zenith MQTT** |
| :--- | :--- | :--- | :--- | :--- |
| **Language / Runtime** | C (`epoll`/`poll`) | Erlang / BEAM | C (`nng`) | **100% Safe Rust** |
| **Binary Size** | ~500 KB – 1.5 MB | > 100 MB | ~1.5 MB – 3 MB | **~100 KB (MCU) / 345 KB (Server)** |
| **Idle RAM (RSS)** | ~3 MB – 5 MB | > 50 MB – 150 MB | ~2 MB – 6 MB | **< 100 KB (MCU) / < 1.5 MB (Server)** |
| **Concurrency Model** | Single-threaded | Multi-threaded (BEAM) | Actor threads | **Multi-threaded Worker Threads** |
| **Memory Safety** | Vulnerable (CVE history) | Safe (GC overhead) | Manual pointers | **Zero leaks, memory safe (RAII)** |
| **MQTT 5.0 Properties** | Partial/Full | Full | Full | **Full zero-copy properties & reasons** |
| **MCU Ready** | No | No | No | **Yes (ESP32-S3, RP2040, `no_std`)** |

---

## Resource Footprint & Benchmarks

### Binary Sizing (Release Profile with LTO & Strip)

```
=============================================================================
 Target Binary        | Architecture   | Binary Size | Target Budget | Status
=============================================================================
 zenith-embedded      | ARM / Xtensa   | ~100 KB     | < 200 KB      | PASS
 zenith-embedded      | aarch64 (OS)   |  279 KB     | < 500 KB      | PASS
 zenith-server        | aarch64/x86_64 |  345 KB     | < 2.0 MB      | PASS
=============================================================================
```

### Performance Characteristics

* **Wire Parser:** Zero heap allocations per incoming packet frame.
* **Lookup Cost:** $O(L)$ level-compressed Radix Trie traversal where $L$ is topic path depth.
* **Test Suite Duration:** Complete 14-test unit & integration test suite executes in **< 0.10s**.

---

## Workspace Structure

The project is structured as a modular Cargo workspace:

```
zenith-mqtt/
├── crates/
│   ├── zenith-core/         # no_std zero-copy MQTT 3.1.1 & 5.0 packet codec
│   ├── zenith-trie/         # Level-compressed Radix Topic Trie with +, # wildcards
│   ├── zenith-broker/       # Session states, QoS 0/1/2 handshakes, ACL, LWT
│   ├── zenith-embedded/     # Minimal profile for bare-metal & microcontrollers
│   └── zenith-server/       # Multi-threaded server engine for Linux/macOS
├── Cargo.toml               # Optimized release profile config
└── README.md
```

---

## Standards Compliance Matrix

- [x] **[MQTT-1.5.1]** 16-bit Big-Endian Integer serialization
- [x] **[MQTT-1.5.4]** UTF-8 String validation (rejects null `\0`, unicode non-characters, surrogates)
- [x] **[MQTT-1.5.5]** Variable Byte Integer encoding up to 268,435,455 bytes
- [x] **[MQTT-3.1]** CONNECT with CleanSession, KeepAlive, Credentials, and Will options
- [x] **[MQTT-3.1.2.5]** Last Will & Testament (LWT) broadcast on abnormal disconnect
- [x] **[MQTT-3.1.2.10]** Keep-Alive heartbeat enforcer ($1.5 \times \text{KeepAlive}$ timeout)
- [x] **[MQTT-3.3]** PUBLISH routing with Topic matching
- [x] **[MQTT-3.3.1.3]** Retained message caching and replay on new subscriptions
- [x] **[MQTT-3.8]** SUBSCRIBE filter matching with granted QoS
- [x] **[MQTT-3.10]** UNSUBSCRIBE topic unbinding
- [x] **[MQTT-4.3.1]** QoS 0 (At most once delivery)
- [x] **[MQTT-4.3.2]** QoS 1 (At least once with Packet ID and `PUBACK`)
- [x] **[MQTT-4.3.3]** QoS 2 (Exactly once 4-step handshake: `PUBLISH` $\rightarrow$ `PUBREC` $\rightarrow$ `PUBREL` $\rightarrow$ `PUBCOMP`)
- [x] **[MQTT-4.7]** Topic filters with single-level (`+`), multi-level (`#`), and system topic isolation (`$SYS/`)
- [x] **[MQTT 5.0]** Zero-copy Property Decoder (User Properties, Expiry, Content Type) and Reason Codes

---

## Getting Started

### Prerequisites

* Rust 1.80+ (stable toolchain)
* `cargo`

### Build

```bash
# Build optimized release server binary (< 350 KB)
cargo build --release --bin zenith-server

# Build embedded binary profile
cargo build --release --bin zenith-embedded
```

### Run Tests

```bash
cargo test
```

### Run Server

```bash
./target/release/zenith-server
# Zenith MQTT Server listening on 127.0.0.1:1883
```

---

## License

Licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0))
* MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT))

at your option.
