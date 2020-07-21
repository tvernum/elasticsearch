/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security;

import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.test.rest.yaml.ObjectPath;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

public class OperatorAdminClusterSettingsIT extends RestUserFilterTestCase {

    @Before
    public void createUsers() throws IOException {
        // Create a mimic of the builtin user, but it should not act as an operator due to a different realm
        createUser(OPERATOR_CREDENTIALS.principal(), OPERATOR_CREDENTIALS.credentials(), List.of("superuser"));
    }

    @After
    public void cleanUp() throws IOException {
        deleteUser(OPERATOR_CREDENTIALS.principal());
    }

    public void testModifySettingsAsOperator() throws Exception {
        checkUser(OPERATOR_CREDENTIALS);

        final Request getRequest = request("GET", "/_cluster/settings", OPERATOR_CREDENTIALS);
        final Response getResponse1 = client().performRequest(getRequest);

        assertThat(entityAsMap(getResponse1), Matchers.hasKey("transient"));

        final Request putRequest = request("PUT", "/_cluster/settings", OPERATOR_CREDENTIALS);
        putRequest.setJsonEntity("{ \"transient\": { \"logger.org.elasticsearch.dummy.operator\" : \"DEBUG\" } }");

        final Response putResponse = client().performRequest(putRequest);
        ObjectPath putResult = ObjectPath.createFromResponse(putResponse);
        assertThat(putResult.evaluate("transient.logger.org.elasticsearch.dummy.operator"), Matchers.equalTo("DEBUG"));

        final Response getResponse2 = client().performRequest(getRequest);
        ObjectPath getResult = ObjectPath.createFromResponse(getResponse2);
        assertThat(getResult.evaluate("transient.logger.org.elasticsearch.dummy.operator"), Matchers.equalTo("DEBUG"));
    }

    public void testModifySettingsAsAdmin() throws Exception {
        checkUser(ADMIN_CREDENTIALS);

        final Request getRequest = request("GET", "/_cluster/settings", ADMIN_CREDENTIALS);

        final Response getResponse1 = client().performRequest(getRequest);
        assertThat(entityAsMap(getResponse1), Matchers.hasKey("transient"));

        final Request putRequest =    request("PUT", "/_cluster/settings", ADMIN_CREDENTIALS);
        putRequest.setJsonEntity("{ \"transient\": { \"logger.org.elasticsearch.dummy.admin\" : \"DEBUG\" } }");

        ResponseException putEx = expectThrows(ResponseException.class, () -> client().performRequest(putRequest));
        assertThat(putEx.getResponse().getStatusLine().getStatusCode(), equalTo(403));
        assertThat(putEx.getMessage(), containsString("/_cluster/settings"));
        assertThat(putEx.getMessage(), containsString(ADMIN_CREDENTIALS.principal()));

        final Response getResponse2 = client().performRequest(getRequest);
        ObjectPath getResult = ObjectPath.createFromResponse(getResponse2);
        assertThat(getResult.evaluate("transient.logger.org.elasticsearch.dummy.admin"), Matchers.nullValue());
    }

    private void checkUser(UsernamePasswordToken userToken) throws IOException {
        Map<String, Object> whoami = entityAsMap(client().performRequest(request("GET", "/_security/_authenticate", userToken)));
        assertThat(whoami.get("username"), equalTo(userToken.principal()));
    }
}
