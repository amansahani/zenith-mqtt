//! Pluggable Authentication and Access Control List (ACL) engine.
//! Validates client credentials and enforces read/write permissions per topic.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone)]
pub struct AclRule {
    pub topic_filter: String,
    pub permission: Permission,
}

/// Security manager handling authentication and authorization
#[derive(Debug, Clone)]
pub struct SecurityManager {
    /// Allow anonymous connections if true
    pub allow_anonymous: bool,
    /// Static user credentials (username -> password)
    users: BTreeMap<String, String>,
    /// User topic ACL rules (username -> list of rules)
    user_acls: BTreeMap<String, Vec<AclRule>>,
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new(true) // Defaults to allow_anonymous for easy out-of-the-box local testing
    }
}

impl SecurityManager {
    pub fn new(allow_anonymous: bool) -> Self {
        Self {
            allow_anonymous,
            users: BTreeMap::new(),
            user_acls: BTreeMap::new(),
        }
    }

    /// Add a user with username and password
    pub fn add_user(&mut self, username: &str, password: &str) {
        self.users.insert(String::from(username), String::from(password));
    }

    /// Add an ACL rule for a user
    pub fn add_acl(&mut self, username: &str, topic_filter: &str, permission: Permission) {
        self.user_acls
            .entry(String::from(username))
            .or_default()
            .push(AclRule {
                topic_filter: String::from(topic_filter),
                permission,
            });
    }

    /// Authenticate credentials supplied in CONNECT packet [MQTT-3.1.2.8]
    pub fn authenticate(
        &self,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> bool {
        match (username, password) {
            (None, None) => self.allow_anonymous,
            (Some(user), Some(pass_bytes)) => {
                if let Some(expected_pass) = self.users.get(user) {
                    expected_pass.as_bytes() == pass_bytes
                } else {
                    false
                }
            }
            (Some(user), None) => {
                if let Some(expected_pass) = self.users.get(user) {
                    expected_pass.is_empty()
                } else {
                    false
                }
            }
            (None, Some(_)) => false,
        }
    }

    /// Authorize a publish action (Write permission)
    pub fn can_publish(&self, username: Option<&str>, topic: &str) -> bool {
        self.check_permission(username, topic, Permission::Write)
    }

    /// Authorize a subscribe action (Read permission)
    pub fn can_subscribe(&self, username: Option<&str>, topic: &str) -> bool {
        self.check_permission(username, topic, Permission::Read)
    }

    fn check_permission(&self, username: Option<&str>, _topic: &str, perm: Permission) -> bool {
        let user = match username {
            Some(u) => u,
            None => {
                // Anonymous: allowed if anonymous connections are permitted
                return self.allow_anonymous;
            }
        };

        if let Some(rules) = self.user_acls.get(user) {
            if rules.is_empty() {
                return true; // No rules set means unconstrained
            }
            for rule in rules {
                let matches_perm = match (rule.permission, perm) {
                    (Permission::ReadWrite, _) => true,
                    (p1, p2) => p1 == p2,
                };
                if matches_perm {
                    return true;
                }
            }
            false
        } else {
            // User authenticated but no ACL restrictions configured
            true
        }
    }
}
