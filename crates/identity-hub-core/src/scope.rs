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

/// Splits a space-delimited scope string into its individual scope aliases,
/// per RFC 6749 ยง3.3's own "scope" convention (a list of space-delimited,
/// case-sensitive strings) - the same convention the real `dcp-tck`'s own
/// `SecureTokenServerImpl.obtainReadToken` uses when it joins more than one
/// requested scope with `String.join(" ", scopes)` before calling a Secure
/// Token Service's `/token` endpoint, and the shape this bootstrap's own
/// embedded STS (`identity_hub_core::sts::issue_token`) echoes back
/// verbatim into a minted access token's `scope` claim. Used to recover the
/// individual scope aliases out of a caller's own *granted* scope (the
/// nested access-token's `scope` claim) so they can be run back through
/// [`ScopeMatcher::credential_types`] exactly like a request's own `scope`
/// array - see `identity-hub-http::handlers::presentation_query`'s
/// scope-escalation check.
pub fn split_scope_string(scopes: &str) -> Vec<String> {
    scopes.split_whitespace().map(|s| s.to_string()).collect()
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

    #[test]
    fn split_scope_string_splits_multiple_space_delimited_aliases() {
        assert_eq!(
            split_scope_string(
                "org.eclipse.dspace.dcp.vc.type:MembershipCredential org.eclipse.dspace.dcp.vc.type:SensitiveDataCredential"
            ),
            vec![
                "org.eclipse.dspace.dcp.vc.type:MembershipCredential".to_string(),
                "org.eclipse.dspace.dcp.vc.type:SensitiveDataCredential".to_string(),
            ]
        );
    }

    #[test]
    fn split_scope_string_handles_a_single_scope_with_no_delimiter() {
        assert_eq!(
            split_scope_string("org.eclipse.dspace.dcp.vc.type:MembershipCredential"),
            vec!["org.eclipse.dspace.dcp.vc.type:MembershipCredential".to_string()]
        );
    }

    #[test]
    fn split_scope_string_of_an_empty_string_is_empty() {
        assert!(split_scope_string("").is_empty());
    }

    #[test]
    fn granted_scope_intersects_with_requested_types_via_credential_types() {
        // End-to-end within this module: a granted scope string round-trips
        // through split_scope_string + credential_types exactly like a
        // request's own `scope` array does - the two are meant to be
        // directly comparable (see handlers::presentation_query).
        let matcher = ScopeMatcher::default_pattern();
        let granted = split_scope_string("org.eclipse.dspace.dcp.vc.type:MembershipCredential");
        let granted_types = matcher.credential_types(&granted);
        assert_eq!(granted_types, vec!["MembershipCredential".to_string()]);
    }
}
