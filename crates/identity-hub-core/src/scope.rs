//! Extracts a requested credential type from a DCP scope string, per
//! `verifiable.presentation.protocol.md#the-orgeclipsedspacedcpvctype-alias`:
//! a scope of the form `org.eclipse.dspace.dcp.vc.type:<Type>[:<suffix>]`
//! denotes access to the VC type `<Type>`. The default pattern matches the
//! real `dcp-tck`'s own default
//! (`dataspacetck.vc.scope.pattern`, see `eclipse-dataspacetck/dcp-tck`'s
//! README, section 2.1.3) exactly, including its named `type`/`suffix`
//! groups, so this bootstrap's scope handling lines up with what the TCK
//! actually sends without extra configuration.

use regex::Regex;

pub const DEFAULT_SCOPE_PATTERN: &str =
    r"org[.]eclipse[.]dspace[.]dcp[.]vc[.]type:(?P<type>[^:]+)(?P<suffix>:.+)?";

pub struct ScopeMatcher {
    pattern: Regex,
}

impl ScopeMatcher {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: Regex::new(pattern)?,
        })
    }

    pub fn default_pattern() -> Self {
        Self::new(DEFAULT_SCOPE_PATTERN).expect("DEFAULT_SCOPE_PATTERN is a valid regex")
    }

    /// The requested credential type for one scope string, or `None` if it
    /// doesn't match this matcher's pattern at all (an unrecognized scope
    /// alias, per the spec, matches nothing rather than erroring).
    pub fn credential_type(&self, scope: &str) -> Option<String> {
        self.pattern
            .captures(scope)
            .and_then(|c| c.name("type"))
            .map(|m| m.as_str().to_string())
    }

    /// Every distinct credential type named across `scopes`.
    pub fn credential_types(&self, scopes: &[String]) -> Vec<String> {
        let mut types: Vec<String> = scopes
            .iter()
            .filter_map(|s| self.credential_type(s))
            .collect();
        types.dedup();
        types
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_type_from_the_vc_type_alias() {
        let matcher = ScopeMatcher::default_pattern();
        assert_eq!(
            matcher.credential_type("org.eclipse.dspace.dcp.vc.type:MembershipCredential"),
            Some("MembershipCredential".to_string())
        );
        assert_eq!(
            matcher.credential_type("org.eclipse.dspace.dcp.vc.type:MembershipCredential:read"),
            Some("MembershipCredential".to_string())
        );
    }

    #[test]
    fn unrecognized_scope_matches_nothing() {
        let matcher = ScopeMatcher::default_pattern();
        assert_eq!(matcher.credential_type("some-other-scope-alias"), None);
    }
}
