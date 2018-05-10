/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.action.token;

import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.SecuritySettingsSourceField;
import org.elasticsearch.xpack.core.security.action.token.CreateTokenRequest;
import org.elasticsearch.xpack.core.security.action.token.CreateTokenResponse;
import org.elasticsearch.xpack.security.rest.action.oauth2.RestGetTokenAction;
import org.hamcrest.Matchers;

import java.io.IOException;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;

public class CreateTokenRequestTests extends ESTestCase {

    public void testRequestValidation() {
        CreateTokenRequest request = new CreateTokenRequest();
        ActionRequestValidationException ve = request.validate();
        assertNotNull(ve);
        assertEquals(1, ve.validationErrors().size());
        assertThat(ve.validationErrors().get(0), containsString("[password, refresh_token]"));
        assertThat(ve.validationErrors().get(0), containsString("grant_type"));

        request.setGrantType("password");
        ve = request.validate();
        assertNotNull(ve);
        assertEquals(2, ve.validationErrors().size());
        assertThat(ve.validationErrors(), hasItem("username is missing"));
        assertThat(ve.validationErrors(), hasItem("password is missing"));

        request.setUsername(randomBoolean() ? null : "");
        request.setPassword(randomBoolean() ? null : new SecureString(new char[]{}));

        ve = request.validate();
        assertNotNull(ve);
        assertEquals(2, ve.validationErrors().size());
        assertThat(ve.validationErrors(), hasItem("username is missing"));
        assertThat(ve.validationErrors(), hasItem("password is missing"));

        request.setUsername(randomAlphaOfLengthBetween(1, 256));
        ve = request.validate();
        assertNotNull(ve);
        assertEquals(1, ve.validationErrors().size());
        assertThat(ve.validationErrors(), hasItem("password is missing"));

        request.setPassword(new SecureString(randomAlphaOfLengthBetween(1, 256).toCharArray()));
        ve = request.validate();
        assertNull(ve);

        request.setRefreshToken(randomAlphaOfLengthBetween(1, 10));
        ve = request.validate();
        assertNotNull(ve);
        assertEquals(1, ve.validationErrors().size());
        assertThat(ve.validationErrors().get(0), containsString("refresh_token is not supported"));

        request.setGrantType("refresh_token");
        ve = request.validate();
        assertNotNull(ve);
        assertEquals(2, ve.validationErrors().size());
        assertThat(ve.validationErrors(), hasItem(containsString("username is not supported")));
        assertThat(ve.validationErrors(), hasItem(containsString("password is not supported")));

        request.setUsername(null);
        request.setPassword(null);
        ve = request.validate();
        assertNull(ve);

        request.setRefreshToken(null);
        ve = request.validate();
        assertNotNull(ve);
        assertEquals(1, ve.validationErrors().size());
        assertThat(ve.validationErrors(), hasItem("refresh_token is missing"));
    }

    public void testParser() throws Exception {
        final String request = "{" +
            "\"grant_type\": \"password\"," +
            "\"username\": \"user1\"," +
            "\"password\": \"" + SecuritySettingsSourceField.TEST_PASSWORD + "\"," +
            "\"scope\": \"FULL\"" +
            "}";
        try (XContentParser parser = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, request)) {
            CreateTokenRequest createTokenRequest = CreateTokenRequest.fromXContent(parser);
            assertEquals("password", createTokenRequest.getGrantType());
            assertEquals("user1", createTokenRequest.getUsername());
            assertEquals("FULL", createTokenRequest.getScope());
            assertTrue(SecuritySettingsSourceField.TEST_PASSWORD_SECURE_STRING.equals(createTokenRequest.getPassword()));
        }
    }

    public void testParserRefreshRequest() throws Exception {
        final String token = randomAlphaOfLengthBetween(4, 32);
        final String request = "{" +
            "\"grant_type\": \"refresh_token\"," +
            "\"refresh_token\": \"" + token + "\"," +
            "\"scope\": \"FULL\"" +
            "}";
        try (XContentParser parser = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, request)) {
            CreateTokenRequest createTokenRequest = CreateTokenRequest.fromXContent(parser);
            assertEquals("refresh_token", createTokenRequest.getGrantType());
            assertEquals(token, createTokenRequest.getRefreshToken());
            assertEquals("FULL", createTokenRequest.getScope());
            assertNull(createTokenRequest.getUsername());
            assertNull(createTokenRequest.getPassword());
        }
    }
    public void testToFromJsonWithUsernamePassword() throws Exception {
        final CreateTokenRequest request = new CreateTokenRequest(
            "password", // grant_type
            randomAlphaOfLengthBetween(6, 12), // username
            new SecureString(randomAlphaOfLengthBetween(8, 16).toCharArray()), // password
            randomBoolean() ? null : randomAlphaOfLengthBetween(2, 6), // scope
            null
        );
        doTestToFromJson(request);
    }
    public void testToFromJsonWithRefreshToken() throws Exception {
        final CreateTokenRequest request = new CreateTokenRequest(
            "refresh_token", // grant_type
            null, // username
            null, // password
            randomBoolean() ? null : randomAlphaOfLengthBetween(2, 6), // scope
            randomAlphaOfLengthBetween(16, 24)
        );
        doTestToFromJson(request);
    }

    private void doTestToFromJson(CreateTokenRequest request1) throws IOException {
        String json1 = Strings.toString(request1);
        assertThat(json1, Matchers.containsString(request1.getGrantType()));

        final CreateTokenRequest request2 = CreateTokenRequest.fromXContent(createParser(XContentType.JSON.xContent(), json1));
        String json2 = Strings.toString(request2);

        assertEquals(json1, json2);
    }
}
