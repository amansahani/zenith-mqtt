//! Memory-compact, high-performance MQTT Topic Trie.
//! Conforming to ISO/IEC 20922:2016 topic filter rules:
//! - Exact topic matching (e.g., `sport/tennis/player1`)
//! - Single-level wildcard `+` (e.g., `sport/+/player1`)
//! - Multi-level wildcard `#` (e.g., `sport/#`)
//! - Leading `$` special topic isolation (e.g., `$SYS/`)

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// A subscription entry mapped to a client ID and its granted QoS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubEntry<ID: Clone + PartialEq> {
    pub client_id: ID,
    pub qos: u8,
}

/// A node in the topic trie.
#[derive(Debug, Clone)]
pub struct TrieNode<ID: Clone + PartialEq> {
    /// Level name, e.g. "sport", "+", or "#"
    pub level: String,
    /// Direct subscribers at this exact level
    pub subscribers: Vec<SubEntry<ID>>,
    /// Child nodes (exact topic levels)
    pub children: Vec<TrieNode<ID>>,
    /// Child node specifically for single-level wildcard '+'
    pub plus_child: Option<Box<TrieNode<ID>>>,
    /// Child node specifically for multi-level wildcard '#'
    pub hash_child: Option<Box<TrieNode<ID>>>,
}

impl<ID: Clone + PartialEq> TrieNode<ID> {
    pub fn new(level: &str) -> Self {
        Self {
            level: String::from(level),
            subscribers: Vec::new(),
            children: Vec::new(),
            plus_child: None,
            hash_child: None,
        }
    }
}

/// The main Topic Trie supporting fast lookups and wildcard matches.
#[derive(Debug, Clone)]
pub struct TopicTrie<ID: Clone + PartialEq> {
    root: TrieNode<ID>,
    /// Special isolated root for topics starting with '$' (e.g., $SYS)
    dollar_root: TrieNode<ID>,
}

impl<ID: Clone + PartialEq> Default for TopicTrie<ID> {
    fn default() -> Self {
        Self::new()
    }
}

impl<ID: Clone + PartialEq> TopicTrie<ID> {
    pub fn new() -> Self {
        Self {
            root: TrieNode::<ID>::new(""),
            dollar_root: TrieNode::<ID>::new("$"),
        }
    }

    /// Subscribe a client to a topic filter with QoS [MQTT-4.7].
    pub fn subscribe(&mut self, topic_filter: &str, client_id: ID, qos: u8) {
        if topic_filter.is_empty() {
            return;
        }

        let is_dollar = topic_filter.starts_with('$');
        let mut curr: &mut TrieNode<ID> = if is_dollar {
            &mut self.dollar_root
        } else {
            &mut self.root
        };

        let levels: Vec<&str> = topic_filter.split('/').collect();

        for level in levels {
            match level {
                "+" => {
                    if curr.plus_child.is_none() {
                        curr.plus_child = Some(Box::new(TrieNode::new("+")));
                    }
                    curr = curr.plus_child.as_mut().unwrap();
                }
                "#" => {
                    if curr.hash_child.is_none() {
                        curr.hash_child = Some(Box::new(TrieNode::new("#")));
                    }
                    curr = curr.hash_child.as_mut().unwrap();
                    // '#' must be the last level per [MQTT-4.7.1.2]
                    break;
                }
                exact => {
                    let idx = curr.children.iter().position(|c| c.level.as_str() == exact);
                    let child_idx = match idx {
                        Some(i) => i,
                        None => {
                            curr.children.push(TrieNode::new(exact));
                            curr.children.len() - 1
                        }
                    };
                    curr = &mut curr.children[child_idx];
                }
            }
        }

        // Add or update subscriber
        if let Some(existing) = curr.subscribers.iter_mut().find(|s| s.client_id == client_id) {
            existing.qos = qos;
        } else {
            curr.subscribers.push(SubEntry { client_id, qos });
        }
    }

    /// Unsubscribe a client from a topic filter.
    pub fn unsubscribe(&mut self, topic_filter: &str, client_id: &ID) {
        if topic_filter.is_empty() {
            return;
        }

        let is_dollar = topic_filter.starts_with('$');
        let mut curr: &mut TrieNode<ID> = if is_dollar {
            &mut self.dollar_root
        } else {
            &mut self.root
        };

        let levels: Vec<&str> = topic_filter.split('/').collect();

        for level in levels {
            match level {
                "+" => {
                    if let Some(ref mut child) = curr.plus_child {
                        curr = child;
                    } else {
                        return;
                    }
                }
                "#" => {
                    if let Some(ref mut child) = curr.hash_child {
                        curr = child;
                        break;
                    } else {
                        return;
                    }
                }
                exact => {
                    if let Some(child) = curr.children.iter_mut().find(|c| c.level.as_str() == exact) {
                        curr = child;
                    } else {
                        return;
                    }
                }
            }
        }

        curr.subscribers.retain(|s| &s.client_id != client_id);
    }

    /// Matches a concrete publish topic against all active subscriptions.
    /// Deduplicates matching subscribers, keeping the highest QoS granted.
    pub fn match_topic(&self, topic: &str) -> Vec<SubEntry<ID>> {
        let mut matches: Vec<SubEntry<ID>> = Vec::new();
        if topic.is_empty() {
            return matches;
        }

        let is_dollar = topic.starts_with('$');
        let root = if is_dollar {
            &self.dollar_root
        } else {
            &self.root
        };

        let levels: Vec<&str> = topic.split('/').collect();
        Self::traverse(root, &levels, &mut matches);

        // Deduplicate: if a client matched multiple filters (e.g. `sport/+` and `sport/#`),
        // MQTT spec specifies delivery with the maximum QoS granted among matching subscriptions.
        let mut deduped: Vec<SubEntry<ID>> = Vec::with_capacity(matches.len());
        for entry in matches {
            if let Some(existing) = deduped.iter_mut().find(|e| e.client_id == entry.client_id) {
                if entry.qos > existing.qos {
                    existing.qos = entry.qos;
                }
            } else {
                deduped.push(entry);
            }
        }

        deduped
    }

    fn traverse(
        node: &TrieNode<ID>,
        levels: &[&str],
        results: &mut Vec<SubEntry<ID>>,
    ) {
        // Multi-level wildcard '#' matches the current level and all remaining sub-levels [MQTT-4.7.1.2]
        if let Some(ref hash_node) = node.hash_child {
            for sub in &hash_node.subscribers {
                results.push(sub.clone());
            }
        }

        if levels.is_empty() {
            // Reached the exact end of topic levels
            for sub in &node.subscribers {
                results.push(sub.clone());
            }
            return;
        }

        let current_level = levels[0];
        let remaining_levels = &levels[1..];

        // 1. Traverse exact matching children
        if let Some(child) = node.children.iter().find(|c| c.level.as_str() == current_level) {
            Self::traverse(child, remaining_levels, results);
        }

        // 2. Traverse single-level wildcard '+' child [MQTT-4.7.1.3]
        if let Some(ref plus_node) = node.plus_child {
            Self::traverse(plus_node, remaining_levels, results);
        }
    }
}
