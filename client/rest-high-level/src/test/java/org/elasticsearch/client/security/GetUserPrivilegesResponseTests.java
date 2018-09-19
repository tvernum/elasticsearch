/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.client.security;

import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.test.ESTestCase;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.emptyIterable;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.iterableWithSize;

public class GetUserPrivilegesResponseTests extends ESTestCase {

    public void testParse() throws Exception {
        String json = "{" +
            "\"cluster\":[\"manage\",\"manage_security\",\"monitor\"]," +
            "\"global\":[" +
            " {\"application\":{\"manage\":{\"applications\":[\"test-*\"]}}}," +
            " {\"application\":{\"manage\":{\"applications\":[\"apps-*\"]}}}" +
            "]," +
            "\"indices\":[" +
            " {\"names\":[\"test-1-*\"],\"privileges\":[\"read\"]}," +
            " {\"names\":[\"test-4-*\"],\"privileges\":[\"read\"],\"field_security\":[{\"grant\":[\"*\"],\"except\":[\"private-*\"]}]}," +
            " {\"names\":[\"test-6-*\",\"test-7-*\"],\"privileges\":[\"read\"]," +
            "  \"query\":[\"{\\\"term\\\":{\\\"test\\\":true}}\"]}," +
            " {\"names\":[\"test-2-*\"],\"privileges\":[\"read\"]," +
            "  \"field_security\":[{\"grant\":[\"*\"],\"except\":[\"secret-*\",\"private-*\"]},{\"grant\":[\"apps-*\"]}]," +
            "  \"query\":[\"{\\\"term\\\":{\\\"test\\\":true}}\",\"{\\\"term\\\":{\\\"apps\\\":true}}\"]}," +
            " {\"names\":[\"test-3-*\",\"test-6-*\"],\"privileges\":[\"read\",\"write\"]}," +
            " {\"names\":[\"test-3-*\",\"test-4-*\",\"test-5-*\"],\"privileges\":[\"read\"]," +
            "  \"field_security\":[{\"grant\":[\"test-*\"]}]}," +
            " {\"names\":[\"test-1-*\",\"test-9-*\"],\"privileges\":[\"all\"]}" +
            "]," +
            "\"applications\":[" +
            " {\"application\":\"app-dne\",\"privileges\":[\"all\"],\"resources\":[\"*\"]}," +
            " {\"application\":\"test-app\",\"privileges\":[\"read\"],\"resources\":[\"object/1\",\"object/2\"]}," +
            " {\"application\":\"test-app\",\"privileges\":[\"user\",\"dne\"],\"resources\":[\"*\"]}" +
            "]," +
            "\"run_as\":[\"app-*\",\"test-*\"]}";
        final XContentParser parser = createParser(XContentType.JSON.xContent(), json);
        final GetUserPrivilegesResponse response = GetUserPrivilegesResponse.fromXContent(parser);

        assertThat(response.getCluster(), contains("manage", "manage_security", "monitor"));

        assertThat(response.getGlobal().size(), equalTo(2));
        assertThat(response.getGlobal().get(0).getCategory(), equalTo("application"));
        assertThat(response.getGlobal().get(0).getConditions().keySet(), contains("manage"));
        assertThat(response.getGlobal().get(1).getCategory(), equalTo("application"));
        assertThat(response.getGlobal().get(1).getConditions().keySet(), contains("manage"));

        assertThat(response.getIndex().size(), equalTo(7));
        assertThat(response.getIndex().get(0).getNames(), contains("test-1-*"));
        assertThat(response.getIndex().get(0).getPrivileges(), contains("read"));
        assertThat(response.getIndex().get(0).getFieldSecurity(), emptyIterable());
        assertThat(response.getIndex().get(0).getQuery(), emptyIterable());

        assertThat(response.getIndex().get(1).getNames(), contains("test-4-*"));
        assertThat(response.getIndex().get(1).getPrivileges(), contains("read"));
        assertThat(response.getIndex().get(1).getFieldSecurity(), iterableWithSize(1));
        assertThat(response.getIndex().get(1).getFieldSecurity().get(0).getGrant(), contains("*"));
        assertThat(response.getIndex().get(1).getFieldSecurity().get(0).getExcept(), contains("private-*"));
        assertThat(response.getIndex().get(1).getQuery(), emptyIterable());

        assertThat(response.getIndex().get(3).getNames(), contains("test-2-*"));
        assertThat(response.getIndex().get(3).getPrivileges(), contains("read"));
        assertThat(response.getIndex().get(3).getFieldSecurity(), iterableWithSize(2));
        assertThat(response.getIndex().get(3).getFieldSecurity().get(0).getGrant(), contains("*"));
        assertThat(response.getIndex().get(3).getFieldSecurity().get(0).getExcept(), contains("secret-*", "private-*"));
        assertThat(response.getIndex().get(3).getFieldSecurity().get(1).getGrant(), contains("apps-*"));
        assertThat(response.getIndex().get(3).getFieldSecurity().get(1).getExcept(), emptyIterable());
        assertThat(response.getIndex().get(3).getQuery(), iterableWithSize(2));
        assertThat(response.getIndex().get(3).getQuery().get(0), equalTo("{\"term\":{\"test\":true}}"));
        assertThat(response.getIndex().get(3).getQuery().get(1), equalTo("{\"term\":{\"apps\":true}}"));

        assertThat(response.getIndex().get(6).getNames(), contains("test-1-*", "test-9-*"));
        assertThat(response.getIndex().get(6).getPrivileges(), contains("all"));
        assertThat(response.getIndex().get(6).getFieldSecurity(), emptyIterable());
        assertThat(response.getIndex().get(6).getQuery(), emptyIterable());

        assertThat(response.getApplication().size(), equalTo(3));
        assertThat(response.getApplication().get(1).getApplication(), equalTo("test-app"));
        assertThat(response.getApplication().get(1).getPrivileges(), contains("read"));
        assertThat(response.getApplication().get(1).getResources(), contains("object/1", "object/2"));

        assertThat(response.getRunAs(), contains("app-*", "test-*"));
    }
}
