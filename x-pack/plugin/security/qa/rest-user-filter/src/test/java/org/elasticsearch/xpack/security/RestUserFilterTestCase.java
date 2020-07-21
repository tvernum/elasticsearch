/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security;

import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.security.DeleteUserRequest;
import org.elasticsearch.client.security.PutUserRequest;
import org.elasticsearch.client.security.RefreshPolicy;
import org.elasticsearch.client.security.user.User;
import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.test.rest.ESRestTestCase;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.junit.BeforeClass;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.util.List;

import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.basicAuthHeaderValue;

public abstract class RestUserFilterTestCase extends ESRestTestCase {

    protected UsernamePasswordToken ADMIN_CREDENTIALS = new UsernamePasswordToken("admin_access",
        new SecureString("admin-password".toCharArray()));
    protected UsernamePasswordToken OPERATOR_CREDENTIALS = new UsernamePasswordToken("operator_access",
        new SecureString("operator-password".toCharArray()));

    private RestHighLevelClient highLevelAdminClient;

    private static Path httpTrustStore;

    @Override
    protected String getProtocol() {
        return "https";
    }

    @BeforeClass
    public static void findTrustStore() throws Exception {
        final URL resource = RestUserFilterTestCase.class.getResource("/ssl/ca.p12");
        if (resource == null) {
            throw new FileNotFoundException("Cannot find classpath resource /ssl/ca.p12");
        }
        httpTrustStore = PathUtils.get(resource.toURI());
    }

    @Override
    protected Settings restAdminSettings() {
        String token = basicAuthHeaderValue("full_access", new SecureString("full-password".toCharArray()));
        return Settings.builder()
            .put(ThreadContext.PREFIX + ".Authorization", token)
            .put(TRUSTSTORE_PATH, httpTrustStore)
            .put(TRUSTSTORE_PASSWORD, "password")
            .build();
    }

    @Override
    protected Settings restClientSettings() {
        // No user by default because we want to be explicit in each test
        return Settings.builder()
            .put(TRUSTSTORE_PATH, httpTrustStore)
            .put(TRUSTSTORE_PASSWORD, "password")
            .build();
    }

    protected Request request(String method, String endpoint, UsernamePasswordToken credentials) {
        Request request = new Request(method, endpoint);
        request.setOptions(RequestOptions.DEFAULT.toBuilder().addHeader("Authorization", credentials.basicAuthHeaderValue()));
        return request;
    }

    protected void createUser(String username, SecureString password, List<String> roles) throws IOException {
        final RestHighLevelClient client = getHighLevelAdminClient();
        client.security().putUser(PutUserRequest.withPassword(new User(username, roles), password.getChars(), true,
            RefreshPolicy.WAIT_UNTIL), RequestOptions.DEFAULT);
    }

    protected void deleteUser(String username) throws IOException {
        final RestHighLevelClient client = getHighLevelAdminClient();
        client.security().deleteUser(new DeleteUserRequest(username), RequestOptions.DEFAULT);
    }

    private RestHighLevelClient getHighLevelAdminClient() {
        if (highLevelAdminClient == null) {
            highLevelAdminClient = new RestHighLevelClient(
                adminClient(),
                ignore -> {
                },
                List.of()) {
            };
        }
        return highLevelAdminClient;
    }
}
