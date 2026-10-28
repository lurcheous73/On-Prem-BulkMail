import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/** Local-only PKCS12 rechain using Xeams' own TLS-field decoder.
 * Does not emit, export, or alter the existing password or private key.
 * AppConfig.xml and the original store are read only; output must be new.
 */
public final class GrangeRenewalKeystore {
    private static String stage = "arguments";
    // The named parser on Canada CT100 was inspected independently. Its TLS
    // field calls TGlob.decryptPassword(value, 8), not the obfuscated B API.
    private static final String NAMED_ADAPTER_SHA256 = "20b8c0ecf30b35ac01ea3528323ba031282af5f9dfdee12ee075bf78377bcadb";
    private static final String NAMED_DECODER_SHA256 = "8ed43780ff20276dc8f59cdba0dd2d5b1b7aee8113be2113cf93fddabc722f16";

    private static void require(boolean good) {
        if (!good) throw new IllegalStateException();
    }

    private static Element single(Document doc, String name) {
        NodeList nodes = doc.getElementsByTagName(name);
        require(nodes.getLength() == 1);
        return (Element) nodes.item(0);
    }

    private static String classResourceHash(String resource) throws Exception {
        InputStream input = GrangeRenewalKeystore.class.getResourceAsStream(resource);
        if (input == null) return null;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try {
            byte[] buffer = new byte[8192];
            int count, total = 0;
            while ((count = input.read(buffer)) != -1) {
                total += count;
                require(total <= 2 * 1024 * 1024);
                digest.update(buffer, 0, count);
            }
        } finally {
            input.close();
        }
        StringBuilder hex = new StringBuilder();
        for (byte value : digest.digest()) {
            hex.append("0123456789abcdef".charAt((value & 0xff) >>> 4));
            hex.append("0123456789abcdef".charAt(value & 0x0f));
        }
        return hex.toString();
    }

    private static String nativeTlsPassword(String value) throws Exception {
        String parserHash = classResourceHash("/com/synametrics/xeams/util/AppConfigAdapter.class");
        Class<?> type;
        Method method;
        Object receiver;
        if (NAMED_ADAPTER_SHA256.equals(parserHash)) {
            require(NAMED_DECODER_SHA256.equals(classResourceHash("/com/synametrics/commons/util/TGlob.class")));
            type = Class.forName("com.synametrics.commons.util.TGlob");
            require(Modifier.isPublic(type.getModifiers()));
            method = type.getDeclaredMethod("decryptPassword", String.class, int.class);
            require(Modifier.isPublic(method.getModifiers()) && Modifier.isStatic(method.getModifiers()));
            receiver = null;
        } else {
            // This is the separately inspected obfuscated parser's exact API.
            // It already validates on the other three enrolled MXs. A different
            // nonpublic B class (as on Canada CT100) is deliberately rejected.
            type = Class.forName("com.synametrics.commons.util.B");
            require(Modifier.isPublic(type.getModifiers()));
            method = type.getDeclaredMethod("e", String.class, int.class);
            require(Modifier.isPublic(method.getModifiers()) && !Modifier.isStatic(method.getModifiers()));
            receiver = type.getConstructor().newInstance();
        }
        require(method.getReturnType() == String.class);
        Object decoded = method.invoke(receiver, value, 8);
        require(decoded instanceof String);
        return (String) decoded;
    }

    private static char[] tlsPassword(Path config) throws Exception {
        stage = "read_tls_configuration";
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        Document doc = factory.newDocumentBuilder().parse(config.toFile());
        require("PKCS12".equalsIgnoreCase(single(doc, "sslCertKeystoreType").getTextContent().trim()));
        Element node = single(doc, "sslCertificatePassword");
        String value = node.getTextContent();
        require(value != null && !value.isEmpty());
        String encrypted = node.getAttribute("encrypted");
        require(encrypted.isEmpty() || "true".equals(encrypted) || "false".equals(encrypted));
        if ("true".equals(encrypted)) {
            stage = "decode_configured_tls_password";
            // Select only the inspected native TLS decoder for this runtime.
            // Silence library diagnostics rather than exposing config values.
            PrintStream savedOut = System.out, savedErr = System.err;
            ByteArrayOutputStream discarded = new ByteArrayOutputStream();
            PrintStream quiet = new PrintStream(discarded);
            try {
                System.setOut(quiet);
                System.setErr(quiet);
                value = nativeTlsPassword(value);
            } finally {
                System.setOut(savedOut);
                System.setErr(savedErr);
                quiet.close();
                discarded.reset();
            }
        }
        require(!value.isEmpty());
        return value.toCharArray();
    }

    private static void verifyKey(PrivateKey key, X509Certificate certificate) throws Exception {
        String algorithm = key.getAlgorithm();
        String signatureAlgorithm;
        if ("RSA".equalsIgnoreCase(algorithm)) signatureAlgorithm = "SHA256withRSA";
        else if ("EC".equalsIgnoreCase(algorithm)) signatureAlgorithm = "SHA256withECDSA";
        else if ("Ed25519".equalsIgnoreCase(algorithm)) signatureAlgorithm = "Ed25519";
        else if ("DSA".equalsIgnoreCase(algorithm)) signatureAlgorithm = "SHA256withDSA";
        else throw new IllegalStateException();
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(key);
        signer.update(challenge);
        byte[] proof = signer.sign();
        signer.initVerify(certificate.getPublicKey());
        signer.update(challenge);
        require(signer.verify(proof));
    }

    private static void privateFile(Path path) throws Exception {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }

    private static void writePublicLeaf(Path destination, X509Certificate certificate) throws Exception {
        stage = "write_public_reference_leaf";
        String pem = "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(certificate.getEncoded()) +
            "\n-----END CERTIFICATE-----\n";
        Files.write(destination, pem.getBytes(StandardCharsets.US_ASCII), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        privateFile(destination);
    }

    private static void execute(String[] args) throws Exception {
        boolean inspect = args.length == 4 && "--inspect".equals(args[0]);
        require(inspect || args.length == 5);
        Path config = Paths.get(args[inspect ? 1 : 0]), existing = Paths.get(args[inspect ? 2 : 1]);
        Path fullchain = inspect ? null : Paths.get(args[2]);
        Path output = inspect ? null : Paths.get(args[3]);
        Path oldLeaf = Paths.get(args[inspect ? 3 : 4]);
        require(Files.isRegularFile(config) && Files.isRegularFile(existing));
        require(inspect || (Files.isRegularFile(fullchain) && !Files.exists(output)));
        require(!Files.exists(oldLeaf));
        char[] password = tlsPassword(config);
        try {
            stage = "load_existing_pkcs12";
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(existing)) { store.load(input, password); }
            List<String> keyAliases = new ArrayList<String>();
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (store.isKeyEntry(alias)) keyAliases.add(alias);
            }
            require(keyAliases.size() == 1);
            String alias = keyAliases.get(0);
            Key loaded = store.getKey(alias, password);
            require(loaded instanceof PrivateKey);
            PrivateKey key = (PrivateKey) loaded;
            Certificate original = store.getCertificate(alias);
            require(original instanceof X509Certificate);
            X509Certificate originalCert = (X509Certificate) original;
            stage = "validate_existing_private_key";
            verifyKey(key, originalCert);
            if (inspect) {
                writePublicLeaf(oldLeaf, originalCert);
                System.out.println("{\"event\":\"java_keystore_inspected\",\"existing_private_key_validated\":true,\"private_entries\":1}");
                return;
            }

            stage = "read_public_replacement_chain";
            Collection<? extends Certificate> certificates;
            try (InputStream input = Files.newInputStream(fullchain)) {
                certificates = CertificateFactory.getInstance("X.509").generateCertificates(input);
            }
            Certificate[] chain = certificates.toArray(new Certificate[certificates.size()]);
            require(chain.length >= 2 && chain[0] instanceof X509Certificate);
            X509Certificate replacement = (X509Certificate) chain[0];
            replacement.checkValidity();
            require(Arrays.equals(originalCert.getPublicKey().getEncoded(), replacement.getPublicKey().getEncoded()));
            require(replacement.getNotBefore().after(originalCert.getNotBefore()));
            require(replacement.getNotAfter().after(originalCert.getNotAfter()));
            for (int i = 0; i + 1 < chain.length; i++) {
                ((X509Certificate) chain[i]).verify(chain[i + 1].getPublicKey());
            }
            verifyKey(key, replacement);

            stage = "write_temporary_pkcs12";
            // Retain other trusted entries, the original alias, key, and password.
            store.setKeyEntry(alias, key, password, chain);
            try (OutputStream out = Files.newOutputStream(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                store.store(out, password);
            }
            privateFile(output);

            stage = "verify_temporary_pkcs12";
            KeyStore reloaded = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(output)) { reloaded.load(input, password); }
            Key repeated = reloaded.getKey(alias, password);
            require(repeated instanceof PrivateKey && repeated.getEncoded() != null && key.getEncoded() != null);
            require(Arrays.equals(key.getEncoded(), repeated.getEncoded()));
            require(Arrays.equals(replacement.getEncoded(), reloaded.getCertificate(alias).getEncoded()));
            verifyKey((PrivateKey) repeated, replacement);

            writePublicLeaf(oldLeaf, originalCert);
            System.out.println("{\"event\":\"java_keystore_validated\",\"original_private_key_preserved\":true,\"private_entries\":1}");
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public static void main(String[] args) {
        try {
            execute(args);
        } catch (Throwable error) {
            // Error messages/stack traces may embed input. Emit fixed stages only.
            System.out.println("{\"event\":\"java_keystore_blocked\",\"stage\":\"" + stage + "\"}");
            System.exit(1);
        }
    }
}
