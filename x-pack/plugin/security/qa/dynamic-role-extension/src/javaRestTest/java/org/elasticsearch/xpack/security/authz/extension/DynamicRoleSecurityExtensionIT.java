/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.extension;

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

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;

public class DynamicRoleSecurityExtensionIT extends ESRestTestCase {

    private static final String ADMIN_USER = "test-admin";
    private static final String PASSWORD_STR = "x-pack-test-password";
    private static final SecureString PASSWORD = new SecureString(PASSWORD_STR.toCharArray());
    @ClassRule
    public static ElasticsearchCluster cluster = ElasticsearchCluster.local()
        .distribution(DistributionType.DEFAULT)
        .name("test-dynamic-role-cluster")
        .plugin("test-dynamic-role-extension-plugin")
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

    public void testDynamicRoleExtension() throws Exception {
        createPrivileges();
        createBaseRole();
        createUser("user_a", "base");
        createUser("user_b", "none");
        createUser("user_c", "@test");
        createIndex();

        createDoc("a1", "a");
        refresh(adminClient(), "test");

        assertRoles("user_a", "base");
        assertRoles("user_b", "none");
        assertRoles("user_c", "@test");

        assertIndexPrivilege("user_a", "test", "read", true);
        assertIndexPrivilege("user_b", "test", "read", false);
        assertIndexPrivilege("user_c", "test", "read", true);

        assertSearch("user_a", Set.of("a1"));
        assertSearch("user_c", Set.of("a1"));
    }

    private void assertRoles(final String username, String... roles) throws IOException {
        final Map<String, Object> authenticate = entityAsMap(
            client().performRequest(setUserForRequest(new Request("GET", "/_security/_authenticate"), username))
        );
        @SuppressWarnings("unchecked")
        final List<String> actualRoles = asInstanceOf(List.class, authenticate.get("roles"));
        assertThat(actualRoles, containsInAnyOrder(roles));
    }

    private void assertIndexPrivilege(final String username, String index, String privilege, boolean expected) throws IOException {
        final Request request = new Request("GET", "/_security/user/_has_privileges");
        request.setJsonEntity(Strings.format("""
            {
                "index": [
                    { "names": [ "%s" ], "privileges": [ "%s" ] }
                ]
            }
            """, index, privilege));
        setUserForRequest(request, username);
        final Map<String, Object> response = entityAsMap(client().performRequest(request));
        final Boolean hasPrivilege = ObjectPath.eval("index." + index + "." + privilege, response);
        assertThat(hasPrivilege, equalTo(expected));
    }

    private void assertSearch(String user, Set<String> expectDocs) throws IOException {
        final Request request = new Request("GET", "/test/_search");
        setUserForRequest(request, user);
        final Map<String, Object> response = entityAsMap(client().performRequest(request));
        final List<?> hits = ObjectPath.eval("hits.hits", response);
        final List<String> actualDocs = hits.stream().map(h -> ObjectPath.<String>eval("_id", h)).toList();
        assertThat(actualDocs, containsInAnyOrder(expectDocs.toArray(String[]::new)));
    }

    private Request setUserForRequest(Request request, String username) {
        request.setOptions(
            request.getOptions()
                .toBuilder()
                .removeHeader("Authorization")
                .addHeader("Authorization", UsernamePasswordToken.basicAuthHeaderValue(username, PASSWORD))
        );
        return request;
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
                "applications": [
                    { "application": "test", "privileges": [ "read" ], "resources": [ "foo" ] }
                ]
            }
            """);
        adminClient().performRequest(request);
    }

    private void createUser(String name, String role) throws Exception {
        final Request request = new Request("PUT", "/_security/user/" + name);
        request.setJsonEntity(Strings.format("""
            {
                "password": "%s",
                "roles": [ "%s" ]
            }
            """, PASSWORD_STR, role));
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
