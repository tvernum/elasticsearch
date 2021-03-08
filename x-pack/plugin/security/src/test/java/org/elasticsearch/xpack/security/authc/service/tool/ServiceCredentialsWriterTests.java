/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.service.tool;

import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.authc.support.Hasher;
import org.elasticsearch.xpack.security.authc.service.ServiceAccount;
import org.elasticsearch.xpack.security.authc.service.ServiceAccountToken;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ServiceCredentialsWriterTests extends ESTestCase {

    public void testWrite() throws IOException {
        final ServiceCredentialsWriter writer = new ServiceCredentialsWriter(Hasher.PBKDF2);
        final Path path = PathUtils.get("service_credentials");
        if (Files.exists(path)) {
            writer.load(path);
            Files.deleteIfExists(path);
        }
        final ServiceAccount.ServiceAccountId account = new ServiceAccount.ServiceAccountId("elastic", "fleet");
        final SecureString secret = new SecureString("secret");
        final ServiceAccountToken token = new ServiceAccountToken(account, "cloud-fleet-server-ba216ae47cb1", secret);
        writer.add(token);
        writer.write(path);
        System.out.println(path.toAbsolutePath().toString());
        System.out.println("Bearer " + token.asBearerString());
    }


}
