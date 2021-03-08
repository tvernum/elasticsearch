/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Version;
import org.elasticsearch.common.CharArrays;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.InputStreamStreamInput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.security.authc.service.ServiceAccount.ServiceAccountId;
import org.elasticsearch.xpack.security.authc.support.SecurityTokenType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;

/**
 * A decoded credential that may be used to authenticate a {@link ServiceAccount}.
 * It consists of:
 * <ol>
 *   <li>A {@link #getAccount() service account id}</li>
 *   <li>The {@link #getTokenName() name of the token} to be used</li>
 *   <li>The {@link #getSecret() secreet credential} for that token</li>
 * </ol>
 */
public class ServiceAccountToken {

    private static final Version VERSION_MINIMUM = Version.V_8_0_0;

    private static final Logger logger = LogManager.getLogger();

    private final ServiceAccountId account;
    private final String tokenName;
    private final SecureString secret;

    public ServiceAccountToken(ServiceAccountId account, String tokenName, SecureString secret) {
        this.account = account;
        this.tokenName = tokenName;
        this.secret = secret;
    }

    public ServiceAccountId getAccount() {
        return account;
    }

    public String getTokenName() {
        return tokenName;
    }

    public String getQualifiedName() {
        return getAccount().accountName() + '/' + tokenName;
    }

    public SecureString getSecret() {
        return secret;
    }

    public SecureString asBearerString() throws IOException {
        try(
            BytesStreamOutput out = new BytesStreamOutput()) {
            Version.writeVersion(Version.CURRENT, out);
            SecurityTokenType.SERVICE_ACCOUNT.write(out);
            account.write(out);
            out.writeString(tokenName);
            out.writeSecureString(secret);
            out.flush();

            final String base64 = Base64.getEncoder().withoutPadding().encodeToString(out.bytes().toBytesRef().bytes);
            return new SecureString(base64.toCharArray());
        }
    }

    /**
     * Parses a token object from the content of a {@link #asBearerString()} bearer string}.
     * This bearer string would typically be
     * {@link org.elasticsearch.xpack.security.authc.TokenService#extractBearerTokenFromHeader extracted} from an HTTP authorization header.
     * <p>
     * <strong>This method does not validate the credential, it simply parses it.</strong>
     * There is no guarantee that the {@link #getSecret() secret} is valid, or even that the {@link #getAccount() account} exists.
     * </p>
     * @param token A raw token string (if this is from an HTTP header, then the <code>"Bearer "</code> prefix must be removed before
     *              calling this method.
     * @return An unvalidated token object.
     */
    public static ServiceAccountToken tryParseToken(SecureString token) {
        try {
            if (token == null) {
                return null;
            }
            return doParseToken(token);
        } catch (IOException e) {
            logger.debug("Cannot parse possible service account token", e);
            return null;
        }
    }

    private static ServiceAccountToken doParseToken(SecureString token) throws IOException {
        final byte[] bytes = CharArrays.toUtf8Bytes(token.getChars());
        logger.trace("parsing token bytes {}", MessageDigests.toHexString(bytes));
        try (StreamInput in = new InputStreamStreamInput(Base64.getDecoder().wrap(new ByteArrayInputStream(bytes)), bytes.length)) {
            final Version version = Version.readVersion(in);
            in.setVersion(version);
            if (version.before(VERSION_MINIMUM)) {
                logger.trace("token has version {}, but we need at least {}", version, VERSION_MINIMUM);
                return null;
            }
            final SecurityTokenType tokenType = SecurityTokenType.read(in);
            if (tokenType != SecurityTokenType.SERVICE_ACCOUNT) {
                logger.trace("token is of type {}, but we only handle {}", tokenType, SecurityTokenType.SERVICE_ACCOUNT);
                return null;
            }

            final ServiceAccountId account = new ServiceAccountId(in);
            final String tokenName = in.readString();
            final SecureString secret = in.readSecureString();

            return new ServiceAccountToken(account, tokenName, secret);
        }
    }

}
