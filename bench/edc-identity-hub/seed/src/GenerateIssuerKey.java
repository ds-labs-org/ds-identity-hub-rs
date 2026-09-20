import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * One-shot helper: generates a P-256 EC keypair for a dcp-test-env
 * identity (the issuer, or the holder participant), and writes its
 * private JWK and public JWK to disk as separate files so both the
 * identity-hub bootstrap extension (which reads private keys to sign/
 * register) and the issuer-service bootstrap extension (which registers
 * a public key as a DID verification method) can read the same key
 * without the two separate JVMs talking to each other.
 *
 * Usage: java -cp <nimbus-jose-jwt jar> GenerateIssuerKey <output-dir> <key-id>
 */
public class GenerateIssuerKey {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: GenerateIssuerKey <output-dir> <key-id>");
            System.exit(1);
        }
        var outDir = Path.of(args[0]);
        var keyId = args[1];
        Files.createDirectories(outDir);

        var key = new ECKeyGenerator(Curve.P_256)
                .keyID(keyId)
                .generate();

        Files.writeString(outDir.resolve(keyId + "-private.jwk.json"), key.toJSONString());
        Files.writeString(outDir.resolve(keyId + "-public.jwk.json"), key.toPublicJWK().toJSONString());
        System.out.println("Wrote " + keyId + "-private.jwk.json and " + keyId + "-public.jwk.json to " + outDir);
    }
}
