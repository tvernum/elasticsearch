/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.secret;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.io.stream.InputStreamStreamInput;
import org.elasticsearch.common.io.stream.OutputStreamStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.xpack.security.support.SecurityIndexManager;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class SecretsStore {

    private final Logger logger = LogManager.getLogger();

    private final Settings settings;
    private final Client client;
    private final SecurityIndexManager secretsIndex;

    private final SecureRandom secureRandom;

    /**
     * The algorithm used to derive the cipher key from a password.
     */
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA512";

    /**
     * The number of iterations to derive the cipher key.
     */
    private static final int KDF_ITERATIONS = 10_000;

    /**
     * The number of bits for the cipher key.
     * <p>
     * Note: The Oracle JDK 8 ships with a limited JCE policy that restricts key length for AES to 128 bits.
     * This can be increased to 256 bits once minimum java 9 is the minimum java version.
     * See http://www.oracle.com/technetwork/java/javase/terms/readme/jdk9-readme-3852447.html#jce
     */
    private static final int CIPHER_KEY_BITS = 128;

    /**
     * The number of bits for the GCM tag.
     */
    private static final int GCM_TAG_BITS = 128;

    /**
     * The cipher used to encrypt the keystore data.
     */
    private static final String CIPHER_ALGORITHM = "AES";

    /**
     * The mode used with the cipher algorithm.
     */
    private static final String CIPHER_MODE = "GCM";

    /**
     * The padding used with the cipher algorithm.
     */
    private static final String CIPHER_PADDING = "NoPadding";

    public SecretsStore(Settings settings, Client client, SecurityIndexManager secretsIndex) {
        this.settings = settings;
        this.client = client;
        this.secretsIndex = secretsIndex;
        this.secureRandom = new SecureRandom();
    }

    public void readSecrets(SecretId id, SecureString password, ActionListener<Secret> listener) {
        if (secretsIndex.indexExists() == false) {
            listener.onFailure(new NoSuchSecretException(id));
            return;
        }
        secretsIndex.checkIndexVersionThenExecute(listener::onFailure, () -> {
            GetRequest getRequest = new GetRequest(secretsIndex.aliasName(), documentId(id));
            client.get(getRequest, ActionListener.delegateFailure(listener, (ignore, response) -> {
                if (response.isExists()) {
                    buildSecret(id, password, response, listener);
                } else {
                    listener.onFailure(new NoSuchSecretException(id));
                }
            }));
        });
    }

    public void writeSecrets(SecretId id, DocWriteRequest.OpType opType, Map<String, Object> content, SecureString password,
                             ActionListener<DocWriteResponse.Result> listener) {
        secretsIndex.prepareIndexIfNeededThenExecute(listener::onFailure, () -> {
            IndexRequest indexRequest = new IndexRequest(secretsIndex.aliasName()).id(documentId(id)).opType(opType);
            indexRequest.source(buildDocument(id, content, password));
            client.index(indexRequest, ActionListener.delegateFailure(listener, (ignore, response) -> {
                switch (response.getResult()) {
                    case CREATED:
                    case UPDATED:
                        listener.onResponse(response.getResult());
                        return;
                    default:
                        logger.debug("Document write failed [{}]", response);
                        listener.onFailure(new ElasticsearchSecurityException("Failed to write secret: " + response.getResult()));
                        return;
                }
            }));
        });
    }

    private Map<String, ?> buildDocument(SecretId id, Map<String, Object> content, SecureString password) {
        try {
            final Map<String, Object> doc = new LinkedHashMap<>();
            doc.put("namespace", id.namespace);
            doc.put("id", id.id);
            doc.put("last_modified", Instant.now().toEpochMilli());
            doc.put("format", "elasticsearch-secrets-v1");
            byte[] salt = generateSalt();
            byte[] iv = generateInitVector();

            final ByteArrayOutputStream bytesStream = new ByteArrayOutputStream();
            final Cipher cipher = buildCipher(Cipher.ENCRYPT_MODE, password, salt, iv);
            try (CipherOutputStream cipherStream = new CipherOutputStream(bytesStream, cipher);
                 StreamOutput out = new OutputStreamStreamOutput(cipherStream)) {
                out.writeMap(content);
            }
            byte[] encryptedBytes = bytesStream.toByteArray();

            final Base64.Encoder encoder = Base64.getEncoder();
            doc.put("salt", encoder.encodeToString(salt));
            doc.put("iv", encoder.encodeToString(iv));
            doc.put("secret", encoder.encodeToString(encryptedBytes));

            return doc;
        } catch (Exception e) {
            logger.warn(new ParameterizedMessage("Failed to build secret [{}]", id), e);
            if (e instanceof ElasticsearchSecurityException) {
                throw (ElasticsearchSecurityException) e;
            } else {
                throw new ElasticsearchSecurityException("Failed to build secret", e);
            }
        }
    }

    private void buildSecret(SecretId id, SecureString password, GetResponse response, ActionListener<Secret> listener) {
        try {
            final Map<String, Object> source = response.getSource();
            checkFieldValue(id, source, "namespace", id.namespace);
            checkFieldValue(id, source, "id", id.id);
            checkFieldValue(id, source, "format", "elasticsearch-secrets-v1");

            final byte[] encryptedSecret = readBinaryField(id, source, "secret");
            final byte[] salt = readBinaryField(id, source, "salt");
            final byte[] iv = readBinaryField(id, source, "iv");

            Cipher cipher = buildCipher(Cipher.DECRYPT_MODE, password, salt, iv);
            try (ByteArrayInputStream bytesStream = new ByteArrayInputStream(encryptedSecret);
                 CipherInputStream cipherStream = new CipherInputStream(bytesStream, cipher);
                 StreamInput in = new InputStreamStreamInput(cipherStream)) {
                final Map<String, Object> secretValue = in.readMap();
                listener.onResponse(new Secret(id, secretValue));
            }
        } catch (Exception e) {
            logger.warn(new ParameterizedMessage("Failed to parse secret [{}]", id), e);
            if (e instanceof ElasticsearchSecurityException) {
                listener.onFailure(e);
            } else {
                listener.onFailure(new ElasticsearchSecurityException("Failed to parse secret", e));
            }
        }
    }

    // @TODO This is basically a clone of the code in KeyStoreWrapper. Should merge them
    private Cipher buildCipher(int mode, SecureString password, byte[] salt, byte[] iv) throws GeneralSecurityException {
        logger.info(
            "Build Cipher: [M={}] [P={}] [S={}] [IV={}]",
            mode,
            password,
            MessageDigests.toHexString(salt),
            MessageDigests.toHexString(iv)
        );

        PBEKeySpec keySpec = new PBEKeySpec(password.getChars(), salt, KDF_ITERATIONS, CIPHER_KEY_BITS);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
        SecretKey secretKey;
        try {
            secretKey = keyFactory.generateSecret(keySpec);
        } catch (Error e) {
            // Security Providers might throw a subclass of Error in FIPS 140 mode, if some prerequisite like
            // salt, iv, or password length is not met. We catch this because we don't want the JVM to exit.
            throw new GeneralSecurityException("Error generating an encryption key from the provided password", e);
        }
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), CIPHER_ALGORITHM);

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM + "/" + CIPHER_MODE + "/" + CIPHER_PADDING);
        cipher.init(mode, secret, spec);
        cipher.updateAAD(salt);
        return cipher;
    }

    private void checkFieldValue(SecretId id, Map<String, Object> source, String fieldName, String expectedValue) {
        final String val = readStringField(id, source, fieldName);
        if (expectedValue.equals(val) == false) {
            throw BadSecretException.badFieldValue(id, fieldName, val, expectedValue);
        }
    }

    private String readStringField(SecretId id, Map<String, Object> source, String fieldName) {
        return readFieldValue(id, source, fieldName, String.class);
    }

    private byte[] readBinaryField(SecretId id, Map<String, Object> source, String fieldName) {
        final String encoded = readStringField(id, source, fieldName);
        try {
            return Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new BadSecretException(id, "Field [" + fieldName + "] is not a base64 encoded value", e);
        }
    }

    private <T> T readFieldValue(SecretId id, Map<String, Object> source, String fieldName, Class<T> type) {
        final Object val = source.get(fieldName);
        if (val == null) {
            throw BadSecretException.missingField(id, fieldName);
        } else if (type.isInstance(val)) {
            return type.cast(val);
        } else {
            throw BadSecretException.badFieldType(id, fieldName, val.getClass(), String.class);
        }
    }

    private byte[] generateSalt() {
        return randomBytes(32);
    }

    private byte[] generateInitVector() {
        return randomBytes(12);
    }

    private byte[] randomBytes(int length) {
        final byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    static String documentId(SecretId id) {
        return "secret$" + encodeId(id.namespace) + "$" + encodeId(id.id);
    }

    private static String encodeId(String idPart) {
        final byte[] idBytes = idPart.getBytes(StandardCharsets.UTF_8);
        final byte[] digest = MessageDigests.sha256().digest(idBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public static class SecretId {
        public final String namespace;
        public final String id;

        public SecretId(String namespace, String id) {
            this.namespace = Objects.requireNonNull(namespace);
            this.id = Objects.requireNonNull(id);
        }

        @Override
        public String toString() {
            return namespace + '/' + id;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            SecretId secretId = (SecretId) o;
            return namespace.equals(secretId.namespace) && id.equals(secretId.id);
        }

        @Override
        public int hashCode() {
            return Objects.hash(namespace, id);
        }
    }

    public static class Secret {
        private final SecretId id;
        private final Map<String, Object> content;

        public Secret(SecretId id, Map<String, Object> content) {
            this.id = id;
            this.content = content;
        }

        public SecretId getId() {
            return id;
        }

        public Map<String, Object> getContent() {
            return content;
        }
    }

    public static class NoSuchSecretException extends ElasticsearchSecurityException {
        public NoSuchSecretException(SecretId id) {
            super("Secret [{}] not found", RestStatus.NOT_FOUND, id);
        }
    }

    public static class BadSecretException extends ElasticsearchSecurityException {
        public BadSecretException(SecretId id, String message) {
            super("Secret [{}] is malformed or corrupted: {}", RestStatus.INTERNAL_SERVER_ERROR, id, message);
        }

        public BadSecretException(SecretId id, String message, Exception e) {
            super("Secret [{}] is malformed or corrupted: {}", RestStatus.INTERNAL_SERVER_ERROR, e, id, message);
        }

        public static BadSecretException missingField(SecretId id, String fieldName) {
            return new BadSecretException(id, "Field [" + fieldName + "] is missing");
        }

        public static BadSecretException badFieldValue(SecretId id, String fieldName, Object actualValue, Object expectedValue) {
            return new BadSecretException(id, "Field [" + fieldName + "] should be [" + expectedValue + "], but is [" + actualValue + "]("
                + actualValue.getClass().getName() + ")");
        }

        public static BadSecretException badFieldType(SecretId id, String fieldName, Class<?> actualType, Class<?> expectedType) {
            return new BadSecretException(id,
                "Field [" + fieldName + "] should be of type [" + expectedType + "], but is [" + actualType + "]");
        }
    }
}
