/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.transport;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.ssl.SslKeyConfig;
import org.elasticsearch.common.ssl.SslUtil;
import org.elasticsearch.env.Environment;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.transport.RemoteClusterService;
import org.elasticsearch.xpack.core.ssl.CertParsingUtils;
import org.elasticsearch.xpack.core.ssl.X509KeyPairSettings;
import org.elasticsearch.xpack.security.signature.X509CertificateSignature;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.X509KeyManager;

public class CrossClusterAccessSignatureManager {

    private final Logger logger = LogManager.getLogger(getClass());

    private static final String SETTINGS_PART_SIGNING = "signing";

    public interface Signer {
        X509CertificateSignature sign(byte[] bytes) throws GeneralSecurityException;
    }

    private Map<String, Signer> signerByClusterAlias;

    public CrossClusterAccessSignatureManager(Environment environment) {
        var settings = environment.settings();
        this.signerByClusterAlias = new HashMap<>();
        settings.getGroups(RemoteClusterService.REMOTE_CLUSTER_SETTINGS_PREFIX).forEach((clusterAlias, remoteSettings) -> {
            logger.trace("Found remote cluster config for [{}]: [{}]", clusterAlias, remoteSettings);
            if (remoteSettings.getByPrefix(SETTINGS_PART_SIGNING).isEmpty() == false) {
                final SslKeyConfig keyConfig = CertParsingUtils.createKeyConfig(
                    remoteSettings,
                    SETTINGS_PART_SIGNING + ".",
                    environment,
                    false
                );
                logger.trace("Signing config for [{}] is [{}]", clusterAlias, keyConfig);
                if (keyConfig.hasKeyMaterial()) {
                    Signer signer = buildSigner(keyConfig);
                    if (signer != null) {
                        signerByClusterAlias.put(clusterAlias, signer);
                    }
                }
            }
        });
    }

    public Signer getSigner(String clusterAlias) {
        return signerByClusterAlias.get(clusterAlias);
    }

    private Signer buildSigner(SslKeyConfig keyConfig) {
        final X509KeyManager keyManager = keyConfig.createKeyManager();
        if (keyManager == null) {
            return null;
        }

        final Set<String> aliases = Stream.of("RSA", "EC")
            .map(keyType -> keyManager.getServerAliases(keyType, null))
            .filter(Objects::nonNull)
            .flatMap(Arrays::stream)
            .collect(Collectors.toSet());

        logger.trace("KeyConfig [{}] has compatible entries: [{}]", keyConfig, aliases);

        return switch (aliases.size()) {
            case 0 -> throw new IllegalStateException("Cannot find a signing key in [" + keyConfig + "]");
            case 1 -> {
                final String alias = aliases.iterator().next();
                final X509Certificate[] chain = keyManager.getCertificateChain(alias);
                yield buildSigner(chain[0], keyManager.getPrivateKey(alias));
            }
            default -> throw new IllegalStateException("Multiple signing keys [" + aliases + "] in [" + keyConfig + "]");
        };
    }

    private Signer buildSigner(X509Certificate certificate, PrivateKey privateKey) {
        final String signatureAlgorithm = switch (privateKey.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw new IllegalArgumentException(
                "Unsupported Key Type [" + privateKey.getAlgorithm() + "] for [" + privateKey + "]"
            );
        };

        final String fingerprint = fingerprint(certificate);

        return new Signer() {
            @Override
            public X509CertificateSignature sign(byte[] bytes) throws GeneralSecurityException {
                Signature signature = Signature.getInstance(signatureAlgorithm);
                signature.initSign(privateKey);
                signature.update(bytes);
                final byte[] sigBytes = signature.sign();
                return new X509CertificateSignature(certificate, signatureAlgorithm, new BytesArray(sigBytes));
            }

            @Override
            public String toString() {
                return "Signer{certificate="
                    + certificate.getSubjectX500Principal()
                    + ";"
                    + fingerprint
                    + ", algorithm="
                    + signatureAlgorithm
                    + "}";
            }
        };

    }

    private static String fingerprint(X509Certificate certificate) {
        try {
            return SslUtil.calculateFingerprint(certificate, "SHA-1");
        } catch (CertificateEncodingException e) {
            return "<?>";
        }
    }

    public static Collection<? extends Setting<?>> getSettings() {
        return X509KeyPairSettings.affix(RemoteClusterService.REMOTE_CLUSTER_SETTINGS_PREFIX, SETTINGS_PART_SIGNING + ".", false);
    }

}
