use super::records::UserInfo;

/// Exact author/committer identity rewrite applied during stream filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRewrite {
    pub match_email: Option<Vec<u8>>,
    pub match_name: Option<Vec<u8>>,
    pub replacement_name: Vec<u8>,
    pub replacement_email: Vec<u8>,
    pub rewrite_author: bool,
    pub rewrite_committer: bool,
}

impl IdentityRewrite {
    pub fn new(
        match_email: Option<Vec<u8>>,
        match_name: Option<Vec<u8>>,
        replacement_name: Vec<u8>,
        replacement_email: Vec<u8>,
    ) -> Self {
        Self {
            match_email,
            match_name,
            replacement_name,
            replacement_email,
            rewrite_author: true,
            rewrite_committer: true,
        }
    }

    pub fn applies_to(&self, user: &UserInfo) -> bool {
        self.match_email
            .as_ref()
            .is_none_or(|email| user.email == *email)
            && self
                .match_name
                .as_ref()
                .is_none_or(|name| user.name == *name)
    }

    pub fn apply(&self, user: &mut UserInfo) -> bool {
        if !self.applies_to(user) {
            return false;
        }
        user.name = self.replacement_name.clone();
        user.email = self.replacement_email.clone();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::IdentityRewrite;
    use crate::filterrepo::records::UserInfo;

    #[test]
    fn matches_email_and_rewrites_identity() {
        let rewrite = IdentityRewrite::new(
            Some(b"old@example.test".to_vec()),
            None,
            b"Maintainer".to_vec(),
            b"new@example.test".to_vec(),
        );
        let mut user = UserInfo {
            name: b"Old Author".to_vec(),
            email: b"old@example.test".to_vec(),
            date: b"1 +0000".to_vec(),
        };
        assert!(rewrite.apply(&mut user));
        assert_eq!(user.name, b"Maintainer");
        assert_eq!(user.email, b"new@example.test");
        assert_eq!(user.date, b"1 +0000");
    }
}
