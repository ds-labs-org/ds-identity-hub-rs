//! OpenID for Verifiable Credential Issuance (OID4VCI 1.0) wire shapes and
//! the pure, network-free parts of its proof-of-possession handling - the
//! second issuance protocol this hub speaks, alongside DCP's own Credential
//! Issuance Protocol (`crate::messages`).
//!
//! Field names follow
//! <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>
//! (snake_case, unlike DCP's camelCase): the Credential Offer (section 4.1),
//! the Credential Issuer Metadata (section 12.2), the Token Endpoint's
//! Pre-Authorized Code grant (section 6), the Nonce Endpoint (section 7),
//! and the Credential Endpoint with `jwt` proofs (section 8, Appendix F.1).
//! Only the `jwt_vc_json` credential format and the `jwt` proof type are
//! modelled - the same JWT-only posture `identity-hub-http`'s DCP Storage
//! API already takes (`validation::verify_credential_proofs`).
//!
//! The HTTP side of both roles (Issuer Service as Credential Issuer,
//! Credential Service as Wallet) lives in `identity-hub-http`'s own
//! `oid4vci` module; this module stays free of I/O so its rules are
//! unit-testable on their own.

use std::collections::BTreeMap;

use dcp_core::{DcpKeyPair, b64_encode, now_secs};
use p256::ecdsa::{Signature, signature::Signer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// `grant_type` value of the Pre-Authorized Code flow (section 4.1.1).
pub const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
/// The only credential format this hub issues or accepts over OID4VCI
/// (Appendix A.1.1, "VC Signed as a JWT, Not Using JSON-LD").
pub const FORMAT_JWT_VC_JSON: &str = "jwt_vc_json";
/// Required JOSE `typ` header of a key proof JWT (Appendix F.1).
pub const PROOF_JWT_TYP: &str = "openid4vci-proof+jwt";
/// Custom URI scheme a by-value or by-reference Credential Offer is
/// conveyed in (section 4.1).
pub const CREDENTIAL_OFFER_SCHEME: &str = "openid-credential-offer://";
/// Path of the Credential Issuer Metadata well-known document (section
/// 12.2.2).
pub const CREDENTIAL_ISSUER_WELL_KNOWN: &str = "openid-credential-issuer";
/// Path of the RFC 8414 Authorization Server Metadata well-known document.
pub const AUTHORIZATION_SERVER_WELL_KNOWN: &str = "oauth-authorization-server";

// ---- Credential Offer ----

/// A Credential Offer (section 4.1.1).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<OfferGrants>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct OfferGrants {
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    /// Present when the Wallet must also send a Transaction Code obtained
    /// out of band - describes its shape, never carries its value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCodeDescription>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TxCodeDescription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---- Metadata ----

/// Credential Issuer Metadata (section 12.2.4). Only the parameters this
/// hub reads or writes are modelled; anything else an issuer publishes is
/// ignored on deserialization.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    pub credential_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfiguration>,
}

/// One entry of `credential_configurations_supported` (section 12.2.4).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialConfiguration {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cryptographic_binding_methods_supported: Vec<String>,
    /// Strings for JOSE formats, COSE integers (e.g. `-7`) for `mso_mdoc`,
    /// so kept untyped: one mdoc entry must not fail the whole document.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_signing_alg_values_supported: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<CredentialDefinition>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialDefinition {
    #[serde(rename = "type")]
    pub types: Vec<String>,
}

/// The subset of RFC 8414 Authorization Server Metadata a Wallet needs for
/// the Pre-Authorized Code flow.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_types_supported: Vec<String>,
    #[serde(
        rename = "pre-authorized_grant_anonymous_access_supported",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_grant_anonymous_access_supported: Option<bool>,
    /// RFC 9449 section 5.1: present when the AS accepts DPoP proofs. A
    /// Wallet that sees `ES256` here sender-constrains its token with DPoP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dpop_signing_alg_values_supported: Vec<String>,
}

// ---- Token / Nonce / Credential endpoints ----

/// Successful Token Response (section 6.2).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: u64,
    /// `openid_credential` entries naming the `credential_identifiers` the
    /// Credential Request must then use instead of the configuration id
    /// (section 6.2). Never written by this hub's own Issuer Service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_details: Vec<TokenAuthorizationDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TokenAuthorizationDetail {
    #[serde(rename = "type")]
    pub detail_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_identifiers: Vec<String>,
}

impl TokenResponse {
    /// The credential identifiers the token response bound to
    /// `configuration_id`, if any (section 6.2).
    pub fn credential_identifiers_for(&self, configuration_id: &str) -> Vec<String> {
        self.authorization_details
            .iter()
            .filter(|d| {
                d.detail_type == "openid_credential"
                    && d.credential_configuration_id.as_deref() == Some(configuration_id)
            })
            .flat_map(|d| d.credential_identifiers.iter().cloned())
            .collect()
    }
}

/// Nonce Response (section 7.2).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NonceResponse {
    pub c_nonce: String,
}

/// Credential Request (section 8.2). Accepts both the 1.0 `proofs` object
/// and the single `proof` object earlier drafts (and many deployed wallets)
/// still send, so either shape reaches the same verification path.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CredentialRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proofs: Option<Proofs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SingleProof>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Proofs {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SingleProof {
    pub proof_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<String>,
}

impl CredentialRequest {
    /// Every `jwt` key proof carried by this request, whichever of the two
    /// shapes it used. A `proof` of any other `proof_type` yields nothing,
    /// which the issuer then rejects as a missing proof.
    pub fn jwt_proofs(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .proofs
            .iter()
            .flat_map(|p| p.jwt.iter().map(String::as_str))
            .collect();
        if let Some(single) = &self.proof
            && single.proof_type == "jwt"
            && let Some(jwt) = &single.jwt
        {
            out.push(jwt);
        }
        out
    }
}

/// Credential Response (section 8.3), immediate issuance only.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialResponse {
    #[serde(default)]
    pub credentials: Vec<IssuedCredential>,
    /// Pre-1.0 single-credential shape, read (never written) so a Wallet
    /// can still redeem an offer from an older issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IssuedCredential {
    pub credential: Value,
}

/// OAuth-style error body every OID4VCI endpoint answers a failure with.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

// ---- URL helpers ----

/// Builds the well-known URL for `issuer` per RFC 8414 section 3.1 /
/// OID4VCI section 12.2.2: the `/.well-known/<name>` segment goes between
/// the authority and any path component, never appended after it.
///
/// The two specs differ on a trailing `/`: RFC 8414 removes it before
/// inserting `oauth-authorization-server`, while OID4VCI 1.0 inserts
/// `openid-credential-issuer` into the identifier as is, so an issuer
/// `https://h/tenant/` publishes at `https://h/.well-known/openid-credential-issuer/tenant/`.
pub fn well_known_url(issuer: &str, name: &str) -> Result<String, String> {
    let keeps_trailing_slash = name == CREDENTIAL_ISSUER_WELL_KNOWN;
    let trimmed = issuer.trim_end_matches('/');
    let (scheme, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| format!("issuer identifier '{issuer}' is not an absolute URL"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(format!("issuer identifier '{issuer}' has no host"));
    }
    let slash = if keeps_trailing_slash && !path.is_empty() && issuer.ends_with('/') {
        "/"
    } else {
        ""
    };
    Ok(format!(
        "{scheme}://{authority}/.well-known/{name}{path}{slash}"
    ))
}

// ---- Key proofs ----

/// Signs `payload` as a compact ES256 JWS under an arbitrary protected
/// `header` (`alg` is forced to `ES256`). `dcp_core::sign_jws` only ever
/// writes `{kid, alg}`, which a key proof cannot use: it needs `typ`.
pub fn sign_jws_with_header(mut header: Value, payload: &Value, key_pair: &DcpKeyPair) -> String {
    header["alg"] = json!("ES256");
    let signing_input = format!(
        "{}.{}",
        b64_encode(header.to_string()),
        b64_encode(payload.to_string())
    );
    let signature: Signature = key_pair.signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64_encode(signature.to_bytes()))
}

/// Builds the `jwt` key proof a Wallet sends to `credential_issuer`'s
/// Credential Endpoint (Appendix F.1): `typ` `openid4vci-proof+jwt`, `kid`
/// naming the holder's `did:web` verification method, `aud` the Credential
/// Issuer Identifier, and the issuer's `c_nonce` when it runs a Nonce
/// Endpoint. No `iss`: the Pre-Authorized Code flow here is anonymous.
pub fn build_jwt_proof(
    key_pair: &DcpKeyPair,
    credential_issuer: &str,
    nonce: Option<&str>,
) -> String {
    build_jwt_proof_for_client(
        key_pair,
        credential_issuer,
        nonce,
        None,
        ProofKeyRef::DidUrl,
    )
}

/// How a key proof names the key a credential gets bound to (Appendix F.1:
/// exactly one of `kid` or `jwk`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKeyRef {
    /// `kid` = this service's `did:web` key: the credential is bound to its
    /// DID, which is what DCP presentation needs.
    DidUrl,
    /// `jwk` = the same key inline, for issuers that only bind to raw keys.
    Jwk,
}

impl ProofKeyRef {
    /// Picks the reference a credential configuration can bind to: the DID
    /// whenever the issuer accepts a DID method (or states no restriction),
    /// the bare key otherwise (e.g. `["jwk"]`).
    pub fn for_binding_methods(methods: &[String]) -> Self {
        if methods.is_empty() || methods.iter().any(|m| m == "did" || m.starts_with("did:")) {
            ProofKeyRef::DidUrl
        } else {
            ProofKeyRef::Jwk
        }
    }
}

/// [`build_jwt_proof`], with `iss` set to `client_id` when the Wallet
/// authenticated to the token endpoint as that client (Appendix F.1: `iss`
/// MUST be omitted only for anonymous Pre-Authorized Code access).
pub fn build_jwt_proof_for_client(
    key_pair: &DcpKeyPair,
    credential_issuer: &str,
    nonce: Option<&str>,
    client_id: Option<&str>,
    key: ProofKeyRef,
) -> String {
    let mut payload = json!({
        "aud": credential_issuer,
        "iat": now_secs(),
    });
    if let Some(nonce) = nonce {
        payload["nonce"] = json!(nonce);
    }
    if let Some(client_id) = client_id {
        payload["iss"] = json!(client_id);
    }
    let header = match key {
        ProofKeyRef::DidUrl => json!({"typ": PROOF_JWT_TYP, "kid": key_pair.own_key_id}),
        ProofKeyRef::Jwk => json!({"typ": PROOF_JWT_TYP, "jwk": public_jwk(key_pair)}),
    };
    sign_jws_with_header(header, &payload, key_pair)
}

/// JOSE `typ` of a DPoP proof (RFC 9449 section 4.2).
pub const DPOP_JWT_TYP: &str = "dpop+jwt";
/// `client_assertion_type` of RFC 7523 `private_key_jwt` client
/// authentication.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The public half of `key_pair` as a bare EC JWK, for a JOSE `jwk` header.
fn public_jwk(key_pair: &DcpKeyPair) -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64_encode(key_pair.public_key_xy.0),
        "y": b64_encode(key_pair.public_key_xy.1),
    })
}

/// A DPoP proof JWT (RFC 9449 section 4.2) for one HTTP request: `htm` and
/// `htu` name the request (`htu` without query or fragment), `nonce` is the
/// server-supplied `DPoP-Nonce` when one was demanded, and `access_token`
/// - when the request carries one - is bound through `ath`.
pub fn build_dpop_proof(
    key_pair: &DcpKeyPair,
    htm: &str,
    htu: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> String {
    let htu = htu.split(['?', '#']).next().unwrap_or(htu);
    let mut payload = json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": htm,
        "htu": htu,
        "iat": now_secs(),
    });
    if let Some(nonce) = nonce {
        payload["nonce"] = json!(nonce);
    }
    if let Some(token) = access_token {
        payload["ath"] = json!(b64_encode(Sha256::digest(token.as_bytes())));
    }
    sign_jws_with_header(
        json!({"typ": DPOP_JWT_TYP, "jwk": public_jwk(key_pair)}),
        &payload,
        key_pair,
    )
}

/// An RFC 7523 `private_key_jwt` client assertion: `iss` and `sub` are
/// `client_id`, `aud` the Authorization Server's issuer identifier (as
/// FAPI 2.0 requires), signed with `key_pair` under its DID-URL `kid`.
pub fn build_client_assertion(key_pair: &DcpKeyPair, client_id: &str, audience: &str) -> String {
    let now = now_secs();
    sign_jws_with_header(
        json!({"typ": "JWT", "kid": key_pair.own_key_id}),
        &json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "jti": uuid::Uuid::new_v4().to_string(),
            "iat": now,
            "exp": now + 60,
        }),
        key_pair,
    )
}

/// How the holder key named by a proof's header is to be resolved - the
/// signature itself is verified by the caller, which may need the network
/// for the `did:web` case.
#[derive(Debug, Clone, PartialEq)]
pub enum ProofKey {
    /// `kid` is a DID URL; the holder DID is the part before `#`.
    DidUrl { kid: String, did: String },
    /// `jwk` carries the public key inline; the holder is identified as the
    /// corresponding `did:jwk`.
    Jwk { x: String, y: String, did: String },
}

impl ProofKey {
    pub fn holder_did(&self) -> &str {
        match self {
            ProofKey::DidUrl { did, .. } | ProofKey::Jwk { did, .. } => did,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ProofError {
    #[error("proof is not a decodable JWS: {0}")]
    Malformed(String),
    #[error("proof typ must be '{PROOF_JWT_TYP}'")]
    WrongType,
    #[error("proof alg must be ES256")]
    WrongAlgorithm,
    #[error("proof header must carry exactly one of kid (a DID URL) or jwk (a P-256 key)")]
    NoKey,
    #[error("proof aud does not name this Credential Issuer")]
    WrongAudience,
    #[error("proof iat is missing, in the future, or too old")]
    StaleOrFutureIat,
    #[error("proof carries no nonce, or not the one this issuer handed out")]
    MissingNonce,
}

/// Maximum age of a key proof's `iat`, and the clock-skew tolerance for one
/// in the future - the same 300 s / 30 s windows the DCP side uses for its
/// Self-Issued ID Tokens (`identity-hub-http`'s `auth` module).
pub const PROOF_MAX_AGE_SECS: u64 = 300;
pub const PROOF_IAT_LEEWAY_SECS: u64 = 30;

/// Checks everything about a `jwt` key proof that needs no network and no
/// issuer-side state: header shape (`typ`, `alg`, exactly one key
/// reference), `aud`, and `iat` freshness. Returns the holder key reference
/// and the proof's `nonce` (if any) so the caller can verify the signature
/// and consume the nonce against its own store.
pub fn inspect_jwt_proof(
    proof: &str,
    credential_issuer: &str,
) -> Result<(ProofKey, Option<String>), ProofError> {
    let (_, header, payload) =
        dcp_core::decode_jws_unverified(proof).map_err(ProofError::Malformed)?;
    if header.get("typ").and_then(Value::as_str) != Some(PROOF_JWT_TYP) {
        return Err(ProofError::WrongType);
    }
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(ProofError::WrongAlgorithm);
    }
    let key = match (header.get("kid"), header.get("jwk")) {
        (Some(Value::String(kid)), None) if kid.starts_with("did:") => ProofKey::DidUrl {
            kid: kid.clone(),
            did: kid.split('#').next().unwrap_or(kid).to_string(),
        },
        (None, Some(Value::Object(map))) => {
            let field = |k: &str| map.get(k).and_then(Value::as_str);
            if field("kty") != Some("EC") || field("crv") != Some("P-256") || map.contains_key("d")
            {
                return Err(ProofError::NoKey);
            }
            let (Some(x), Some(y)) = (field("x"), field("y")) else {
                return Err(ProofError::NoKey);
            };
            let public = json!({"kty": "EC", "crv": "P-256", "x": x, "y": y});
            ProofKey::Jwk {
                x: x.to_string(),
                y: y.to_string(),
                did: format!("did:jwk:{}", b64_encode(public.to_string())),
            }
        }
        _ => return Err(ProofError::NoKey),
    };
    let aud_ok = match payload.get("aud") {
        Some(Value::String(aud)) => aud == credential_issuer,
        Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(credential_issuer)),
        _ => false,
    };
    if !aud_ok {
        return Err(ProofError::WrongAudience);
    }
    let now = now_secs();
    match payload.get("iat").and_then(Value::as_u64) {
        Some(iat) if iat <= now + PROOF_IAT_LEEWAY_SECS && iat + PROOF_MAX_AGE_SECS >= now => {}
        _ => return Err(ProofError::StaleOrFutureIat),
    }
    let nonce = payload
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok((key, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://issuer.example";

    fn key_pair() -> DcpKeyPair {
        DcpKeyPair::generate("did:web:holder.example:credential-service".to_string())
    }

    #[test]
    fn proof_key_follows_the_binding_methods() {
        assert_eq!(ProofKeyRef::for_binding_methods(&[]), ProofKeyRef::DidUrl);
        let did = vec!["did:web".to_string(), "jwk".to_string()];
        assert_eq!(ProofKeyRef::for_binding_methods(&did), ProofKeyRef::DidUrl);
        assert_eq!(
            ProofKeyRef::for_binding_methods(&["jwk".to_string()]),
            ProofKeyRef::Jwk
        );
    }

    #[test]
    fn issuer_metadata_accepts_cose_algorithm_identifiers() {
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json!({
            "credential_issuer": "https://issuer.example/tenant/",
            "credential_endpoint": "https://issuer.example/tenant/credential",
            "credential_configurations_supported": {
                "pid_sd_jwt": {
                    "format": "dc+sd-jwt",
                    "credential_signing_alg_values_supported": ["ES256"]
                },
                "pid_mdoc": {
                    "format": "mso_mdoc",
                    "cryptographic_binding_methods_supported": ["cose_key"],
                    "credential_signing_alg_values_supported": [-7]
                }
            }
        }))
        .unwrap();
        assert_eq!(metadata.credential_configurations_supported.len(), 2);
    }

    #[test]
    fn well_known_url_inserts_the_segment_before_the_path() {
        assert_eq!(
            well_known_url("https://issuer.example", CREDENTIAL_ISSUER_WELL_KNOWN).unwrap(),
            "https://issuer.example/.well-known/openid-credential-issuer"
        );
        assert_eq!(
            well_known_url(
                "https://issuer.example/tenant/",
                AUTHORIZATION_SERVER_WELL_KNOWN
            )
            .unwrap(),
            "https://issuer.example/.well-known/oauth-authorization-server/tenant"
        );
        assert_eq!(
            well_known_url(
                "https://issuer.example/tenant/",
                CREDENTIAL_ISSUER_WELL_KNOWN
            )
            .unwrap(),
            "https://issuer.example/.well-known/openid-credential-issuer/tenant/"
        );
        assert_eq!(
            well_known_url("https://issuer.example/", CREDENTIAL_ISSUER_WELL_KNOWN).unwrap(),
            "https://issuer.example/.well-known/openid-credential-issuer"
        );
        assert!(well_known_url("issuer.example", "x").is_err());
    }

    #[test]
    fn credential_offer_round_trips_the_spec_example() {
        let json = r#"{
            "credential_issuer": "https://credential-issuer.example.com",
            "credential_configuration_ids": ["UniversityDegree_LDP_VC"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
                    "tx_code": {"length": 4, "input_mode": "numeric", "description": "PIN"}
                }
            }
        }"#;
        let offer: CredentialOffer = serde_json::from_str(json).unwrap();
        let grant = offer
            .grants
            .as_ref()
            .unwrap()
            .pre_authorized_code
            .as_ref()
            .unwrap();
        assert_eq!(grant.pre_authorized_code, "oaKazRN8I0IbtZ0C7JuMn5");
        assert_eq!(grant.tx_code.as_ref().unwrap().length, Some(4));
        let back: CredentialOffer =
            serde_json::from_value(serde_json::to_value(&offer).unwrap()).unwrap();
        assert_eq!(back, offer);
    }

    #[test]
    fn credential_request_reads_both_proof_shapes() {
        let new: CredentialRequest = serde_json::from_value(json!({
            "credential_configuration_id": "a",
            "proofs": {"jwt": ["p1", "p2"]}
        }))
        .unwrap();
        assert_eq!(new.jwt_proofs(), vec!["p1", "p2"]);
        let old: CredentialRequest = serde_json::from_value(json!({
            "credential_configuration_id": "a",
            "proof": {"proof_type": "jwt", "jwt": "p3"}
        }))
        .unwrap();
        assert_eq!(old.jwt_proofs(), vec!["p3"]);
        let other: CredentialRequest = serde_json::from_value(json!({
            "proof": {"proof_type": "ldp_vp"}
        }))
        .unwrap();
        assert!(other.jwt_proofs().is_empty());
    }

    #[test]
    fn a_built_proof_inspects_cleanly_and_verifies() {
        let kp = key_pair();
        let proof = build_jwt_proof(&kp, ISSUER, Some("n-1"));
        let (key, nonce) = inspect_jwt_proof(&proof, ISSUER).unwrap();
        assert_eq!(nonce.as_deref(), Some("n-1"));
        assert_eq!(
            key.holder_did(),
            "did:web:holder.example:credential-service"
        );
        let vk = kp.signing_key().verifying_key().to_owned();
        dcp_core::verify_jws_signature(&proof, &vk).unwrap();
    }

    #[test]
    fn inspect_rejects_wrong_audience_type_and_stale_iat() {
        let kp = key_pair();
        let proof = build_jwt_proof(&kp, ISSUER, None);
        assert_eq!(
            inspect_jwt_proof(&proof, "https://other.example").unwrap_err(),
            ProofError::WrongAudience
        );

        let untyped = dcp_core::sign_jws(
            &json!({"aud": ISSUER, "iat": now_secs()}),
            &kp.signing_key(),
            &kp.own_key_id,
        );
        assert_eq!(
            inspect_jwt_proof(&untyped, ISSUER).unwrap_err(),
            ProofError::WrongType
        );

        let stale = sign_jws_with_header(
            json!({"typ": PROOF_JWT_TYP, "kid": kp.own_key_id}),
            &json!({"aud": ISSUER, "iat": now_secs() - PROOF_MAX_AGE_SECS - 10}),
            &kp,
        );
        assert_eq!(
            inspect_jwt_proof(&stale, ISSUER).unwrap_err(),
            ProofError::StaleOrFutureIat
        );
    }

    #[test]
    fn inspect_maps_an_inline_jwk_to_a_did_jwk_and_rejects_private_keys() {
        let kp = key_pair();
        let x = b64_encode(kp.public_key_xy.0);
        let y = b64_encode(kp.public_key_xy.1);
        let proof = sign_jws_with_header(
            json!({"typ": PROOF_JWT_TYP, "jwk": {"kty": "EC", "crv": "P-256", "x": x, "y": y}}),
            &json!({"aud": ISSUER, "iat": now_secs()}),
            &kp,
        );
        let (key, _) = inspect_jwt_proof(&proof, ISSUER).unwrap();
        assert!(key.holder_did().starts_with("did:jwk:"));

        let leaky = sign_jws_with_header(
            json!({"typ": PROOF_JWT_TYP, "jwk": {"kty": "EC", "crv": "P-256", "x": x, "y": y, "d": "secret"}}),
            &json!({"aud": ISSUER, "iat": now_secs()}),
            &kp,
        );
        assert_eq!(
            inspect_jwt_proof(&leaky, ISSUER).unwrap_err(),
            ProofError::NoKey
        );
    }
}
