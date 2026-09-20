import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.edc.iam.did.spi.document.Service;
import org.eclipse.edc.iam.verifiablecredentials.spi.VcConstants;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.CredentialFormat;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.CredentialSubject;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.DataModelVersion;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.Issuer;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.VerifiableCredential;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.VerifiableCredentialContainer;
import org.eclipse.edc.identityhub.spi.participantcontext.IdentityHubParticipantContextService;
import org.eclipse.edc.identityhub.spi.participantcontext.model.IdentityHubParticipantContext;
import org.eclipse.edc.identityhub.spi.participantcontext.model.KeyDescriptor;
import org.eclipse.edc.identityhub.spi.participantcontext.model.KeyPairUsage;
import org.eclipse.edc.identityhub.spi.participantcontext.model.ParticipantManifest;
import org.eclipse.edc.identityhub.spi.verifiablecredentials.model.VcStatus;
import org.eclipse.edc.identityhub.spi.verifiablecredentials.model.VerifiableCredentialResource;
import org.eclipse.edc.identityhub.spi.verifiablecredentials.store.CredentialStore;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Bootstrap extension for the "dcp-test-env" (see
 * federated-catalog-rs/compliance/dcp-test-env/README.md): creates one
 * holder participant ("dcp-test-client") in this IdentityHub instance and
 * directly inserts a real, validly-signed JWT-VC into its credential
 * store, so a DCP presentation query against this instance returns a
 * genuine, verifiable presentation for federated-catalog-rs's Rust DCP
 * verifier (and its test client) to exercise.
 *
 * Deliberate simplification, documented in the README: the credential is
 * inserted directly rather than delivered through the live, asynchronous
 * DCP issuance protocol (offer -> holder request -> issuer processes ->
 * callback) between this IdentityHub and the separately-running Issuer
 * Service. The credential's signature is still genuine (signed with the
 * real "issuer" keypair the Issuer Service participant also holds - see
 * IssuerServiceSeedExtension), and everything downstream of it (DID
 * resolution, JWT/VP signature verification, the STS token exchange) is
 * the real DCP wire protocol. Only the issuer<->holder delivery
 * choreography is skipped.
 */
@Extension(IdentityHubSeedExtension.NAME)
public class IdentityHubSeedExtension implements ServiceExtension {
    public static final String NAME = "dcp-test-env seed (IdentityHub)";

    private static final String HOLDER_PARTICIPANT_ID = "dcp-test-client";
    private static final String HOLDER_KEY_ID = "dcp-test-client-key";
    private static final String ISSUER_PARTICIPANT_ID = "issuer";
    private static final String CREDENTIAL_TYPE = "FederatedCatalogAccessCredential";
    /**
     * Stands in for federated-catalog-rs's own DCP identity until that
     * side is implemented. Real DCP's presentation-query protocol
     * requires "proof of original possession": the party that received
     * the holder's self-issued token (the verifier - federated-catalog-rs,
     * eventually) must re-package the token's embedded access-token claim
     * into a *new* self-issued token, signed with the verifier's *own*
     * key, before the holder's Presentation API will accept it (see the
     * README's "why a 'verifier' participant" section). Hosting this
     * identity here, in the same IdentityHub instance being validated,
     * is a test-environment convenience - it does not imply
     * federated-catalog-rs's real DCP implementation will depend on this
     * IdentityHub's STS; it very likely will not (see the README).
     */
    private static final String VERIFIER_PARTICIPANT_ID = "verifier";
    private static final String VERIFIER_KEY_ID = "verifier-key";

    @Inject
    private IdentityHubParticipantContextService participantContextService;

    @Inject
    private CredentialStore credentialStore;

    @Inject
    private Vault vault;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void prepare() {
        var env = new SeedEnv();

        var holderDid = env.didFor(env.identityHubDidHost, HOLDER_PARTICIPANT_ID);
        var issuerDid = env.didFor(env.issuerServiceDidHost, ISSUER_PARTICIPANT_ID);
        var verifierDid = env.didFor(env.identityHubDidHost, VERIFIER_PARTICIPANT_ID);
        var credentialServiceUrl = env.credentialsBaseUrl + "/v1/participants/" + HOLDER_PARTICIPANT_ID;

        var holderResponse = createAndActivateParticipant(
                HOLDER_PARTICIPANT_ID, holderDid, HOLDER_KEY_ID, env.readHolderKey(),
                new Service("credential-service-1", "CredentialService", credentialServiceUrl),
                // PRESENTATION_SIGNING: the holder is the one whose key
                // signs the outgoing VerifiablePresentation JWT itself
                // (VerifiablePresentationServiceImpl.createPresentation),
                // separate from TOKEN_SIGNING which covers the SI/access
                // tokens exchanged via the STS.
                Set.of(KeyPairUsage.TOKEN_SIGNING, KeyPairUsage.PRESENTATION_SIGNING));
        var verifierResponse = createAndActivateParticipant(
                VERIFIER_PARTICIPANT_ID, verifierDid, VERIFIER_KEY_ID, env.readVerifierKey(), null,
                Set.of(KeyPairUsage.TOKEN_SIGNING));

        if (holderResponse != null) {
            env.writeSeedInfo(holderDid, issuerDid, verifierDid,
                    holderResponse.clientId(), holderResponse.clientSecret(),
                    verifierResponse == null ? null : verifierResponse.clientId(),
                    verifierResponse == null ? null : verifierResponse.clientSecret());
        }

        seedCredential(env, holderDid, issuerDid);
    }

    /**
     * Creates + activates a participant context with a single
     * TOKEN_SIGNING key, idempotently (skips if it already exists - the
     * in-memory store means that only matters within one JVM's lifetime,
     * but keeps re-running prepare() harmless either way).
     *
     * @return the creation response (with STS client_id/secret), or null
     *         if the participant already existed (nothing new to report).
     */
    private org.eclipse.edc.identityhub.spi.participantcontext.model.CreateParticipantContextResponse createAndActivateParticipant(
            String participantId, String did, String keyId, ECKey key, Service serviceEndpoint, Set<KeyPairUsage> usages) {
        var existing = participantContextService.getParticipantContext(participantId);
        if (existing.succeeded() && existing.getContent() != null) {
            System.out.println(NAME + ": participant '" + participantId + "' already exists, skipping creation");
            return null;
        }

        var privateKeyAlias = keyId + "-alias";
        // The verification-method id must be the full "did:...#fragment"
        // form, not a bare local id - SelfIssuedTokenVerifier resolves a
        // JWT's "kid" header expecting exactly that shape ("The given ID
        // must conform to 'did:method:identifier[:fragment]'" is the
        // error you get otherwise), and the JWT generator copies
        // whatever KeyDescriptor.keyId() is verbatim into "kid" - so the
        // two have to agree on this fuller form.
        var fullKeyId = did + "#" + keyId;
        // The KeyDescriptor below only *references* this alias - the STS
        // signs tokens by looking the private key up in the Vault at
        // request time, so it has to actually be there before the
        // participant context (and its STS account) can issue anything,
        // or token requests fail with "Private key ... not found in
        // Config".
        var vaultResult = vault.storeSecret(participantId, privateKeyAlias, key.toJSONString());
        if (vaultResult.failed()) {
            throw new RuntimeException("Failed to store private key for '" + participantId + "' in vault: " + vaultResult.getFailureDetail());
        }

        var manifestBuilder = ParticipantManifest.Builder.newInstance()
                .participantContextId(participantId)
                .did(did)
                .active(true)
                .key(KeyDescriptor.Builder.newInstance()
                        .keyId(fullKeyId)
                        .privateKeyAlias(privateKeyAlias)
                        .publicKeyJwk(key.toPublicJWK().toJSONObject())
                        .usage(usages)
                        .build());
        if (serviceEndpoint != null) {
            manifestBuilder.serviceEndpoint(serviceEndpoint);
        }

        var response = participantContextService.createParticipantContext(manifestBuilder.build())
                .orElseThrow(f -> new RuntimeException("Failed to create participant context '" + participantId + "': " + f.getFailureDetail()));

        // ParticipantManifest.active(true) does NOT actually put the
        // context in ACTIVATED state on this version (see
        // IdentityHubParticipantContextServiceImpl.convert(), which
        // unconditionally sets CREATED) - an explicit activation step is
        // required, mirroring how deleteParticipantContext() calls
        // ::deactivate. Without this, DidDocumentServiceImpl refuses to
        // publish the DID document (logged as a warning, not an error)
        // and did:web resolution returns an empty 204.
        var activation = participantContextService.updateParticipant(participantId, IdentityHubParticipantContext::activate);
        if (activation.failed()) {
            throw new RuntimeException("Failed to activate participant context '" + participantId + "': " + activation.getFailureDetail());
        }

        System.out.println(NAME + ": created + activated participant '" + participantId + "' did=" + did);
        return response;
    }

    private void seedCredential(SeedEnv env, String holderDid, String issuerDid) {
        var issuerKey = env.readIssuerKey();

        var vc = VerifiableCredential.Builder.newInstance()
                .id("urn:uuid:" + UUID.randomUUID())
                .contexts(new ArrayList<>(new LinkedHashSet<>(List.of(VcConstants.W3C_CREDENTIALS_URL))))
                .issuer(new Issuer(issuerDid))
                .dataModelVersion(DataModelVersion.V_1_1)
                .issuanceDate(Instant.now())
                .expirationDate(Instant.now().plusSeconds(3600L * 24 * 365))
                .types(List.of("VerifiableCredential", CREDENTIAL_TYPE))
                .credentialSubject(CredentialSubject.Builder.newInstance()
                        .id(holderDid)
                        .claim("participantId", HOLDER_PARTICIPANT_ID)
                        .claim("catalogAccess", List.of("CAT0101", "CAT0102"))
                        .build())
                .build();

        var jwt = signCredential(vc, issuerDid, issuerKey);
        var container = new VerifiableCredentialContainer(jwt, CredentialFormat.VC1_0_JWT, vc);

        var resource = VerifiableCredentialResource.Builder.newHolder()
                .id("vc-" + UUID.randomUUID())
                .participantContextId(HOLDER_PARTICIPANT_ID)
                .holderId(holderDid)
                .issuerId(issuerDid)
                .state(VcStatus.ISSUED)
                .credential(container)
                .build();

        var result = credentialStore.create(resource);
        if (result.failed()) {
            throw new RuntimeException("Failed to store seeded credential: " + result.getFailureDetail());
        }
        System.out.println(NAME + ": seeded " + CREDENTIAL_TYPE + " for " + holderDid + " issued by " + issuerDid);
    }

    /**
     * Signs a JWT-VC by hand with Nimbus, matching the claim shape EDC's
     * own (issuer-service-only, not on this classpath - see the README)
     * JwtCredentialGenerator produces: iss/sub/iat/nbf/jti/exp plus a "vc"
     * claim carrying the credential's JSON-LD body.
     */
    private String signCredential(VerifiableCredential vc, String issuerDid, ECKey issuerKey) {
        try {
            var vcClaim = Map.<String, Object>of(
                    "@context", vc.getContext(),
                    "type", vc.getType(),
                    "id", vc.getId(),
                    "issuanceDate", vc.getIssuanceDate().toString(),
                    "expirationDate", vc.getExpirationDate().toString(),
                    "issuer", issuerDid,
                    "credentialSubject", vc.getCredentialSubject().get(0).getClaims()
            );

            var claims = new JWTClaimsSet.Builder()
                    .issuer(issuerDid)
                    .subject(vc.getCredentialSubject().get(0).getId())
                    .issueTime(Date.from(Instant.now()))
                    .notBeforeTime(Date.from(vc.getIssuanceDate()))
                    .expirationTime(Date.from(vc.getExpirationDate()))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("vc", vcClaim)
                    .build();

            var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(issuerDid + "#" + issuerKey.getKeyID())
                    .build();

            var signedJwt = new SignedJWT(header, claims);
            signedJwt.sign(new ECDSASigner(issuerKey));
            return signedJwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to sign seeded credential", e);
        }
    }

    /**
     * Reads env-configured hosts/keys for this seed run. Kept as a tiny
     * inner helper rather than a full config framework since this is
     * throwaway test-environment bootstrap code, not production
     * extension code.
     */
    private static final class SeedEnv {
        final String identityHubDidHost = require("SEED_IDENTITYHUB_DID_HOST");
        final String issuerServiceDidHost = require("SEED_ISSUER_DID_HOST");
        final String credentialsBaseUrl = require("SEED_CREDENTIALS_BASE_URL");
        final Path keysDir = Path.of(require("SEED_KEYS_DIR"));
        final Path infoFile = Path.of(require("SEED_INFO_FILE"));

        String didFor(String host, String participantId) {
            return "did:web:" + host.replace(":", "%3A") + ":" + participantId;
        }

        ECKey readHolderKey() {
            return readKey("dcp-test-client-key");
        }

        ECKey readIssuerKey() {
            return readKey("issuer-key");
        }

        ECKey readVerifierKey() {
            return readKey("verifier-key");
        }

        private ECKey readKey(String keyId) {
            try {
                var json = Files.readString(keysDir.resolve(keyId + "-private.jwk.json"));
                return ECKey.parse(json);
            } catch (IOException | ParseException e) {
                throw new RuntimeException("Failed to read seed key " + keyId, e);
            }
        }

        void writeSeedInfo(String holderDid, String issuerDid, String verifierDid,
                           String holderClientId, String holderClientSecret,
                           String verifierClientId, String verifierClientSecret) {
            var json = "{\n"
                    + "  \"holderDid\": \"" + holderDid + "\",\n"
                    + "  \"issuerDid\": \"" + issuerDid + "\",\n"
                    + "  \"verifierDid\": \"" + verifierDid + "\",\n"
                    + "  \"holderParticipantId\": \"" + HOLDER_PARTICIPANT_ID + "\",\n"
                    + "  \"verifierParticipantId\": \"" + VERIFIER_PARTICIPANT_ID + "\",\n"
                    + "  \"holderStsClientId\": \"" + holderClientId + "\",\n"
                    + "  \"holderStsClientSecret\": \"" + holderClientSecret + "\",\n"
                    + "  \"verifierStsClientId\": \"" + verifierClientId + "\",\n"
                    + "  \"verifierStsClientSecret\": \"" + verifierClientSecret + "\"\n"
                    + "}\n";
            try {
                Files.writeString(infoFile, json);
            } catch (IOException e) {
                throw new RuntimeException("Failed to write seed info file", e);
            }
        }

        private static String require(String envVar) {
            var value = System.getenv(envVar);
            if (value == null || value.isBlank()) {
                throw new RuntimeException("Missing required env var " + envVar + " for dcp-test-env seeding");
            }
            return value;
        }
    }
}
