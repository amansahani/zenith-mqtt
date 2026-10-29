#[cfg(test)]
mod tests {
    use zenith_trie::trie::{SubEntry, TopicTrie};

    #[test]
    fn test_exact_topic_matching() {
        let mut trie = TopicTrie::new();
        trie.subscribe("sensor/temperature/room1", "client_a", 1);
        trie.subscribe("sensor/humidity/room1", "client_b", 0);

        let matches = trie.match_topic("sensor/temperature/room1");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], SubEntry { client_id: "client_a", qos: 1 });

        let nomatch = trie.match_topic("sensor/pressure/room1");
        assert!(nomatch.is_empty());
    }

    #[test]
    fn test_single_level_wildcard() {
        let mut trie = TopicTrie::new();
        trie.subscribe("sport/+/player1", "client_tennis", 1);

        let matches1 = trie.match_topic("sport/tennis/player1");
        assert_eq!(matches1.len(), 1);
        assert_eq!(matches1[0].client_id, "client_tennis");

        let matches2 = trie.match_topic("sport/cricket/player1");
        assert_eq!(matches2.len(), 1);
        assert_eq!(matches2[0].client_id, "client_tennis");

        // Single '+' must not span multiple levels
        let matches3 = trie.match_topic("sport/tennis/wimbledon/player1");
        assert!(matches3.is_empty());
    }

    #[test]
    fn test_multi_level_wildcard() {
        let mut trie = TopicTrie::new();
        trie.subscribe("factory/#", "client_monitor", 2);

        let m1 = trie.match_topic("factory/line1/temp");
        assert_eq!(m1.len(), 1);
        assert_eq!(m1[0].client_id, "client_monitor");

        let m2 = trie.match_topic("factory/line2/press/sensor5/val");
        assert_eq!(m2.len(), 1);
        assert_eq!(m2[0].client_id, "client_monitor");
        assert_eq!(m2[0].qos, 2);

        // Disjoint path
        let m3 = trie.match_topic("office/temp");
        assert!(m3.is_empty());
    }

    #[test]
    fn test_deduplication_highest_qos() {
        let mut trie = TopicTrie::new();
        // Client subscribes with both general (#) at QoS 0 and specific at QoS 2
        trie.subscribe("sport/#", "client_all", 0);
        trie.subscribe("sport/tennis/+", "client_all", 2);

        let matches = trie.match_topic("sport/tennis/final");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].client_id, "client_all");
        assert_eq!(matches[0].qos, 2); // Deduped to maximum QoS granted
    }

    #[test]
    fn test_unsubscribe() {
        let mut trie = TopicTrie::new();
        trie.subscribe("home/lights", "app", 1);
        assert_eq!(trie.match_topic("home/lights").len(), 1);

        trie.unsubscribe("home/lights", &"app");
        assert!(trie.match_topic("home/lights").is_empty());
    }
}
