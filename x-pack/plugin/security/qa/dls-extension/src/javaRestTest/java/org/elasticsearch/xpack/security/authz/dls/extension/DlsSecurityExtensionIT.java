/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.dls.extension;

import org.elasticsearch.client.Request;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.test.cluster.ElasticsearchCluster;
import org.elasticsearch.test.cluster.local.distribution.DistributionType;
import org.elasticsearch.test.rest.ESRestTestCase;
import org.elasticsearch.xcontent.ObjectPath;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.junit.ClassRule;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsInAnyOrder;

public class DlsSecurityExtensionIT extends ESRestTestCase {

    private static final String ADMIN_USER = "test-admin";
    private static final String PASSWORD_STR = "x-pack-test-password";
    private static final SecureString PASSWORD = new SecureString(PASSWORD_STR.toCharArray());
    @ClassRule
    public static ElasticsearchCluster cluster = ElasticsearchCluster.local()
        .distribution(DistributionType.DEFAULT)
        .name("test-dls-extension-cluster")
        .plugin("test-dls-extension-plugin")
        .setting("xpack.security.enabled", "true")
        .setting("xpack.license.self_generated.type", "trial")
        .user(ADMIN_USER, PASSWORD_STR)
        .build();

    @Override
    protected String getTestRestCluster() {
        return cluster.getHttpAddresses();
    }

    @Override
    protected Settings restClientSettings() {
        return Settings.builder().put(ThreadContext.PREFIX + ".Authorization", basicAuthHeaderValue(ADMIN_USER, PASSWORD)).build();
    }

    public void testDlsExtension() throws Exception {
        createPrivileges();
        createBaseRole();
        createRole("role_a", "a");
        createRole("role_b", "b");
        createRole("role_ac", "a", "c");

        createUser("user_a", "role_a");
        createUser("user_b", "role_b");
        createUser("user_ab", "role_a", "role_b");
        createUser("user_ac", "role_ac");
        createUser("user_abc", "role_ac", "role_b");

        createIndex();
        createDoc("a1", "a");
        createDoc("a2", "a");
        createDoc("a3", "a");
        createDoc("b1", "b");
        createDoc("b2", "b");
        createDoc("c1", "c");
        createDoc("d1", "d");
        refresh(adminClient(), "test");

        assertSearch("user_a", Set.of("a1", "a2", "a3"));
        assertSearch("user_b", Set.of("b1", "b2"));
        assertSearch("user_ab", Set.of("a1", "a2", "a3", "b1", "b2"));
        assertSearch("user_ac", Set.of("a1", "a2", "a3", "c1"));
        assertSearch("user_abc", Set.of("a1", "a2", "a3", "b1", "b2", "c1"));
        assertSearch(ADMIN_USER, Set.of("a1", "a2", "a3", "b1", "b2", "c1", "d1"));
    }

    private void assertSearch(String user, Set<String> expectDocs) throws IOException {
        final Request request = new Request("GET", "/test/_search");
        setUserForRequest(request, user);
        final Map<String, Object> response = entityAsMap(client().performRequest(request));
        final List<?> hits = ObjectPath.eval("hits.hits", response);
        final List<String> actualDocs = hits.stream().map(h -> ObjectPath.<String>eval("_id", h)).toList();
        assertThat(actualDocs, containsInAnyOrder(expectDocs.toArray(String[]::new)));
    }

    private void setUserForRequest(Request request, String username) {
        request.setOptions(
            request.getOptions()
                .toBuilder()
                .removeHeader("Authorization")
                .addHeader("Authorization", UsernamePasswordToken.basicAuthHeaderValue(username, PASSWORD))
        );
    }

    private void createPrivileges() throws Exception {
        final Request request = new Request("PUT", "/_security/privilege/");
        request.setJsonEntity("""
            {
                "test": {
                    "read": {
                        "actions": [
                            "*:read"
                        ]
                    }
                }
            }
            """);
        adminClient().performRequest(request);
    }

    private void createBaseRole() throws Exception {
        final Request request = new Request("PUT", "/_security/role/base");
        request.setJsonEntity("""
            {
                "indices": [
                    { "names": [ "test" ], "privileges": [ "read" ], "query": { "extension": { "name": "test_ext" } } }
                ]
            }
            """);
        adminClient().performRequest(request);
    }

    private void createRole(String name, String... categories) throws Exception {
        final Request request = new Request("PUT", "/_security/role/" + name);
        request.setJsonEntity(Strings.format("""
            {
                "applications": [
                    { "application": "test", "privileges": [ "read" ], "resources": [ %s ] }
                ]
            }
            """, Stream.of(categories).map(s -> '"' + s + '"').collect(Collectors.joining(","))));
        adminClient().performRequest(request);
    }

    private void createUser(String name, String... roles) throws Exception {
        final Request request = new Request("PUT", "/_security/user/" + name);
        request.setJsonEntity(Strings.format("""
            {
                "password": "%s",
                "roles": [ "base", %s ]
            }
            """, PASSWORD_STR, Stream.of(roles).map(s -> '"' + s + '"').collect(Collectors.joining(","))));
        adminClient().performRequest(request);
    }

    private void createIndex() throws Exception {
        String mapping = """
            "properties": {
              "category":{ "type":"keyword" },
              "name":{ "type":"keyword" }
            }
            """;
        createIndex(adminClient(), "test", Settings.EMPTY, mapping);
    }

    private void createDoc(String id, String category) throws Exception {
        Request request = new Request("PUT", "/test/_doc/" + id);
        request.setJsonEntity(Strings.format("""
            {
              "name": "%s",
              "category": "%s"
            }
            """, id, category));
        adminClient().performRequest(request);
    }

}
