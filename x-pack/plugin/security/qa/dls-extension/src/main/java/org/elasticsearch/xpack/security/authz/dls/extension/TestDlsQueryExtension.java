/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.authz.dls.extension;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.Strings;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesAction;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.ResolvedIndices;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.DocumentSecurityQuery;
import org.elasticsearch.xpack.core.security.authz.permission.ResourcePrivileges;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.permission.StaticSecurityQuery;
import org.elasticsearch.xpack.core.security.ext.DlsQueryExtension;
import org.elasticsearch.xpack.core.security.user.User;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class TestDlsQueryExtension implements DlsQueryExtension {

    private static final String CATEGORIES = "categories";
    private final Logger logger = LogManager.getLogger(TestDlsQueryExtension.class);

    private static final String APP_NAME = "test";
    private static final String READ_PRIVILEGE = "category:read";

    private final Client client;

    public TestDlsQueryExtension(Client client) {
        this.client = client;
    }

    @Override
    public String name() {
        return "test_ext";
    }

    @Override
    public DocumentSecurityQuery build(User user, Map<String, Object> config, RequestData data) {
        if (data == null) {
            throw new IllegalStateException("no request data provided");
        }
        final Collection<String> categories = data.get(CATEGORIES);
        if (categories == null) {
            throw new IllegalStateException("request data does not contain [" + CATEGORIES + "]");
        }
        if (categories.isEmpty()) {
            return StaticSecurityQuery.MATCH_NONE;
        }

        final String query = Strings.format("""
            { "terms": { "category": [  %s ] } }
            """, categories.stream().map(s -> '"' + s + '"').collect(Collectors.joining(", ")));
        logger.info("using DLS query [{}]", query);
        return new StaticSecurityQuery(query);
    }

    @Override
    public void precache(Authentication authentication, Role role, ResolvedIndices requestedIndices, ActionListener<RequestData> listener) {
        if (requestedIndices.getLocal().contains(APP_NAME)) {
            final RoleDescriptor.ApplicationResourcePrivileges privileges = RoleDescriptor.ApplicationResourcePrivileges.builder()
                .application(APP_NAME)
                .privileges(READ_PRIVILEGE)
                .resources("a", "b", "c")
                .build();
            final HasPrivilegesRequest req = new HasPrivilegesRequest();
            req.username(authentication.getEffectiveSubject().getUser().principal());
            req.clusterPrivileges(Strings.EMPTY_ARRAY);
            req.indexPrivileges(new RoleDescriptor.IndicesPrivileges[0]);
            req.applicationPrivileges(privileges);
            client.execute(HasPrivilegesAction.INSTANCE, req, listener.map(response -> {
                final List<String> categories = response.getApplicationPrivileges()
                    .get(APP_NAME)
                    .stream()
                    .filter(priv -> priv.getPrivileges().get(READ_PRIVILEGE))
                    .map(ResourcePrivileges::getResource)
                    .toList();
                return new RequestData(Map.of(CATEGORIES, categories));
            }));
        } else {
            listener.onResponse(RequestData.EMPTY);
        }
    }
}
