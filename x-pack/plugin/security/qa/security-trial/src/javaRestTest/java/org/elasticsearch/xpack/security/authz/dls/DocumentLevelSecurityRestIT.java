/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.dls;

import org.elasticsearch.client.Request;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.test.XContentTestUtils;
import org.elasticsearch.xcontent.ObjectPath;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.security.SecurityOnTrialLicenseRestTestCase;
import org.junit.Before;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

public class DocumentLevelSecurityRestIT extends SecurityOnTrialLicenseRestTestCase {

    private static final String USERNAME1 = "u001";
    private static final String USERNAME2 = "u002";

    private static final SecureString USER_PASSWORD = new SecureString("u-password".toCharArray());

    private static final String SHARED_ROLE = "role_shared";
    private static final String ROLE1 = "role_1";
    private static final String ROLE2 = "role_2";

    @Before
    public void setupDLS() throws IOException {
        createUser(USERNAME1, USER_PASSWORD, List.of(SHARED_ROLE, ROLE1), Map.of("department", "sales"));
        createUser(USERNAME2, USER_PASSWORD, List.of(SHARED_ROLE, ROLE2), Map.of("department", "finance"));

        setupRoles();
        setupIndices();
        setupDocuments();
    }

    private void setupRoles() throws IOException {
        createRole(
            SHARED_ROLE, //
            List.of(Tuple.tuple(List.of("index_username_1", "index_username_2"), """
                {
                    "template": {
                        "source": {
                            "term": { "owner" : "{{_user.username}}" }
                        }
                    }
                }
                """), Tuple.tuple(List.of("index_dept"), """
                {
                    "template": {
                        "source": {
                            "term": { "department" : "{{_user.metadata.department}}" }
                        }
                    }
                }
                """), Tuple.tuple(List.of("index_pub_1", "index_pub_2"), """
                { "term": { "public" : true } }
                """))
        );
        createRole(
            ROLE1,
            List.of(
                Tuple.tuple(List.of("index_username_2"), ""), //
                Tuple.tuple(List.of("index_u1"), """
                    { "term": { "user" : "u1" } }
                    """),
                Tuple.tuple(List.of("index_pub_2"), """
                    {
                        "template": {
                            "source": {
                                "bool": {
                                    "should": [
                                        { "term": { "owner" : "{{_user.username}}" } },
                                        { "term": { "public": true } }
                                    ]
                                }
                            }
                        }
                    }
                    """)
            )
        );
        createRole(
            ROLE2,
            List.of(
                Tuple.tuple(List.of("index_u2"), ""),
                Tuple.tuple(List.of("index_pub_2"), "{ \"term\": { \"owner\" : \"" + USERNAME2 + "\" } }}")
            )
        );
    }

    private void setupIndices() throws IOException {
        String mapping = """
            "properties": {
              "owner":{ "type":"keyword" },
              "message":{ "type":"text" }
            }
            """;
        createIndex(adminClient(), "index_username_1", Settings.EMPTY, mapping);
        createIndex(adminClient(), "index_username_2", Settings.EMPTY, mapping);

        mapping = """
            "properties": {
              "department":{ "type":"keyword" },
              "message":{ "type":"text" }
            }
            """;
        createIndex(adminClient(), "index_dept", Settings.EMPTY, mapping);

        mapping = """
            "properties": {
              "owner":{ "type":"keyword" },
              "public":{ "type":"boolean" },
              "message":{ "type":"text" }
            }
            """;
        createIndex(adminClient(), "index_pub_1", Settings.EMPTY, mapping);
        createIndex(adminClient(), "index_pub_2", Settings.EMPTY, mapping);
    }

    private void setupDocuments() throws IOException {
        // index: index_username_1 / inde_username_2
        for (String index : List.of("index_username_1", "index_username_2")) {
            indexDocument(index, "u1_a", Map.ofEntries(Map.entry("owner", USERNAME1), Map.entry("message", randomAlphaOfLength(12))));
            indexDocument(index, "u1_b", Map.ofEntries(Map.entry("owner", USERNAME1), Map.entry("message", randomAlphaOfLength(12))));
            indexDocument(index, "u1_c", Map.ofEntries(Map.entry("owner", USERNAME1), Map.entry("message", randomAlphaOfLength(12))));
            indexDocument(index, "u2_a", Map.ofEntries(Map.entry("owner", USERNAME2), Map.entry("message", randomAlphaOfLength(12))));
            indexDocument(index, "u2_b", Map.ofEntries(Map.entry("owner", USERNAME2), Map.entry("message", randomAlphaOfLength(12))));
            indexDocument(index, "u3_a", Map.ofEntries(Map.entry("owner", "u003"), Map.entry("message", randomAlphaOfLength(12))));        // index:

            refresh(adminClient(), index);
        }

        // index: index_dept
        for (int i = 1; i <= 3; i++) {
            indexDocument(
                "index_dept",
                "sales_" + i,
                Map.ofEntries(Map.entry("department", "sales"), Map.entry("message", randomAlphaOfLength(12)))
            );
        }
        for (int i = 1; i <= 5; i++) {
            indexDocument(
                "index_dept",
                "finance_" + i,
                Map.ofEntries(Map.entry("department", "finance"), Map.entry("message", randomAlphaOfLength(12)))
            );
        }
        refresh(adminClient(), "index_dept");

        // index: index_pub_1 / index_pub_2
        for (String index : List.of("index_pub_1", "index_pub_2")) {
            for (int i = 1; i <= 3; i++) {
                for (Boolean pub : List.of(true, false)) {
                    for (String user : List.of(USERNAME1, USERNAME2)) {
                        indexDocument(
                            index,
                            user + "_" + pub + "_" + i,
                            Map.ofEntries(Map.entry("owner", user), Map.entry("public", pub), Map.entry("message", randomAlphaOfLength(12)))
                        );
                    }
                }
            }
            refresh(adminClient(), index);
        }
    }

    public void testStaticQuery() throws Exception {
        assertCount("index_pub_1", USERNAME1, 6);
        assertCount("index_pub_1", USERNAME2, 6);
    }

    public void testTemplateQuery() throws Exception {
        assertCount("index_username_1", USERNAME1, 3);
        assertCount("index_username_1", USERNAME2, 2);
    }

    public void testMultipleRoles() throws Exception {
        // in index_pub_2 both users can see all of their own documents, but u1 has a template, and u2 does not
        assertCount("index_pub_2", USERNAME1, 9);
        assertCount("index_pub_2", USERNAME2, 9);

        // in "index_username_2" u1 can see all documents because one of their roles has an empty query, but u2 can only their own docs
        assertCount("index_username_2", USERNAME1, 6);
        assertCount("index_username_2", USERNAME2, 2);
    }

    public void testTemplateWithUserMetadata() throws Exception {
        assertCount("index_dept", USERNAME1, 3);
        assertCount("index_dept", USERNAME2, 5);
    }

    private void assertCount(String indexName, String username, int expected) throws IOException {
        Request request = new Request("GET", "/" + indexName + "/_search/");
        setUserForRequest(request, username);
        final Map<String, Object> response = responseAsMap(client().performRequest(request));
        final List<?> hits = ObjectPath.eval("hits.hits", response);
        if (hits.size() != expected) {
            fail(
                String.format("Expected <%d> hits\nBut was <%d>\n%s", expected, hits.size(), Strings.collectionToCommaDelimitedString(hits))
            );
        }
        assertThat(hits, hasSize(expected));
    }

    private void indexDocument(String indexName, String id, Map<String, ?> source) throws IOException {
        Request request = new Request("PUT", "/" + indexName + "/_doc/" + id);
        request.setJsonEntity(XContentTestUtils.convertToXContent(source, XContentType.JSON).utf8ToString());
        adminClient().performRequest(request);
    }

    private void setUserForRequest(Request request, String username) {
        request.setOptions(
            request.getOptions()
                .toBuilder()
                .removeHeader("Authorization")
                .addHeader("Authorization", UsernamePasswordToken.basicAuthHeaderValue(username, USER_PASSWORD))
        );
    }

    private void createUser(String username, SecureString password, List<String> roles, Map<String, Object> metadata) throws IOException {
        getSecurityClient().putUser(
            new User(username, roles.toArray(String[]::new), "User " + username, username + "@example.com", metadata, true),
            password
        );
    }

    protected void createRole(String name, List<Tuple<List<String>, String>> indexQueries) throws IOException {
        final List<RoleDescriptor.IndicesPrivileges> indexPrivileges = indexQueries.stream()
            .map(
                tup -> RoleDescriptor.IndicesPrivileges.builder()
                    .indices(tup.v1())
                    .privileges("read", "monitor", "view_index_metadata")
                    .query(tup.v2().isEmpty() ? null : tup.v2())
                    .build()
            )
            .toList();

        final RoleDescriptor role = new RoleDescriptor(
            name,
            new String[] { "monitor" },
            indexPrivileges.toArray(RoleDescriptor.IndicesPrivileges[]::new),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        );
        getSecurityClient().putRole(role);
    }

}
