/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.xpack.core.security.action.apikey.ApiKey;
import org.elasticsearch.xpack.core.security.authc.CrossClusterAccessSubjectInfo;
import org.elasticsearch.xpack.security.signature.X509CertificateSignature;
import org.elasticsearch.xpack.security.transport.CrossClusterAccessSignatureManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Objects;

public final class CrossClusterAccessHeaders {

    public static final String CROSS_CLUSTER_ACCESS_CREDENTIALS_HEADER_KEY = "_cross_cluster_access_credentials";
    public static final String CROSS_CLUSTER_ACCESS_SIGNATURE_HEADER_KEY = "_cross_cluster_access_signature";

    private final String credentialsHeader;
    private final CrossClusterAccessSubjectInfo crossClusterAccessSubjectInfo;

    public record MaybeSignedHeaders(
        CrossClusterAccessHeaders headers,
        @Nullable X509CertificateSignature signature,
        @Nullable byte[] content
    ) {
        public boolean isSigned() {
            return signature != null;
        }

        public boolean verifySignature() throws GeneralSecurityException {
            assert isSigned();
            final Signature signer = Signature.getInstance(signature.algorithm());
            signer.initVerify(signature.certificate());
            signer.update(content);
            return signer.verify(signature.signature().array());
        }
    }

    public CrossClusterAccessHeaders(String credentialsHeader, CrossClusterAccessSubjectInfo crossClusterAccessSubjectInfo) {
        assert credentialsHeader.startsWith("ApiKey ") : "credentials header must start with [ApiKey ]";
        this.credentialsHeader = credentialsHeader;
        this.crossClusterAccessSubjectInfo = crossClusterAccessSubjectInfo;
    }

    public void writeToContext(final ThreadContext ctx, @Nullable final CrossClusterAccessSignatureManager.Signer signer)
        throws IOException {
        ctx.putHeader(CROSS_CLUSTER_ACCESS_CREDENTIALS_HEADER_KEY, credentialsHeader);
        final String subjectInfo = crossClusterAccessSubjectInfo.encode();
        ctx.putHeader(CrossClusterAccessSubjectInfo.CROSS_CLUSTER_ACCESS_SUBJECT_INFO_HEADER_KEY, subjectInfo);
        if (signer != null) {
            final byte[] bytes = getSignableBytes(credentialsHeader, subjectInfo);
            try {
                final X509CertificateSignature signature = signer.sign(bytes);
                ctx.putHeader(CROSS_CLUSTER_ACCESS_SIGNATURE_HEADER_KEY, signature.encodeToString());
            } catch (GeneralSecurityException e) {
                throw new ElasticsearchSecurityException("Failed to sign cross cluster headers", e);
            }
        }
    }

    private static byte[] getSignableBytes(final String credentials, String subjectInfo) {
        String toSign = credentials + '\n' + subjectInfo;
        return toSign.getBytes(StandardCharsets.UTF_8);
    }

    public static MaybeSignedHeaders readFromContext(final ThreadContext ctx) throws IOException {
        final String credentialsHeader = ctx.getHeader(CROSS_CLUSTER_ACCESS_CREDENTIALS_HEADER_KEY);
        if (credentialsHeader == null) {
            throw new IllegalArgumentException(
                "cross cluster access header [" + CROSS_CLUSTER_ACCESS_CREDENTIALS_HEADER_KEY + "] is required"
            );
        }
        // Invoke parsing logic to validate that the header decodes to a valid API key credential
        // Call `close` since the returned value is an auto-closable
        parseCredentialsHeader(credentialsHeader).close();

        final String subjectInfoString = ctx.getHeader(CrossClusterAccessSubjectInfo.CROSS_CLUSTER_ACCESS_SUBJECT_INFO_HEADER_KEY);
        if (subjectInfoString == null) {
            throw new IllegalArgumentException(
                "cross cluster access header ["
                    + CrossClusterAccessSubjectInfo.CROSS_CLUSTER_ACCESS_SUBJECT_INFO_HEADER_KEY
                    + "] is required"
            );
        }
        final CrossClusterAccessSubjectInfo subjectInfo = CrossClusterAccessSubjectInfo.decode(subjectInfoString);
        final CrossClusterAccessHeaders headers = new CrossClusterAccessHeaders(credentialsHeader, subjectInfo);

        final String signatureString = ctx.getHeader(CROSS_CLUSTER_ACCESS_SIGNATURE_HEADER_KEY);
        if (signatureString == null) {
            return new MaybeSignedHeaders(headers, null, null);
        }

        final X509CertificateSignature signature = X509CertificateSignature.decode(signatureString);
        return new MaybeSignedHeaders(headers, signature, getSignableBytes(credentialsHeader, subjectInfoString));
    }

    public ApiKeyService.ApiKeyCredentials credentials() {
        return parseCredentialsHeader(credentialsHeader);
    }

    static ApiKeyService.ApiKeyCredentials parseCredentialsHeader(final String header) {
        try {
            return Objects.requireNonNull(ApiKeyService.getCredentialsFromHeader(header, ApiKey.Type.CROSS_CLUSTER));
        } catch (Exception ex) {
            throw new IllegalArgumentException(
                "cross cluster access header ["
                    + CROSS_CLUSTER_ACCESS_CREDENTIALS_HEADER_KEY
                    + "] value must be a valid API key credential",
                ex
            );
        }
    }

    public CrossClusterAccessSubjectInfo getCleanAndValidatedSubjectInfo() {
        return crossClusterAccessSubjectInfo.cleanAndValidate();
    }

    // package-private for testing
    CrossClusterAccessSubjectInfo getSubjectInfo() {
        return crossClusterAccessSubjectInfo;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (CrossClusterAccessHeaders) obj;
        return Objects.equals(this.credentialsHeader, that.credentialsHeader)
            && Objects.equals(this.crossClusterAccessSubjectInfo, that.crossClusterAccessSubjectInfo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentialsHeader, crossClusterAccessSubjectInfo);
    }
}
