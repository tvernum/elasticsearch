/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.action.privilege;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.test.SecuritySingleNodeTestCase;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesRequestBuilder;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesResponse;
import org.elasticsearch.xpack.core.security.client.SecurityClient;
import org.hamcrest.Matchers;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.notNullValue;

public class PutPrivilegesActionTests extends SecuritySingleNodeTestCase {

    protected SecurityClient securityClient() {
        return new SecurityClient(client());
    }

    public void testPutPrivileges() throws Exception {
        final PutPrivilegesRequestBuilder requestBuilder = securityClient().preparePutPrivileges(new BytesArray("{ "
            + "\"foo\":{"
            + "  \"read\":{ \"application\":\"foo\", \"name\":\"read\", \"actions\":[ \"data:/read/*\", \"admin:/read/*\" ] },"
            + "  \"write\":{ \"application\":\"foo\", \"name\":\"write\", \"actions\":[ \"data:/write/*\", \"admin:*\" ] },"
            + "  \"all\":{ \"application\":\"foo\", \"name\":\"all\", \"actions\":[ \"*\" ] }"
            + " }"
            + "}"), XContentType.JSON);
        final PutPrivilegesResponse response = requestBuilder.get();
        assertThat(response, notNullValue());
        assertThat(response.created(), hasKey("foo"));
        assertThat(response.created().get("foo"), containsInAnyOrder("read", "write", "all"));
    }

}
