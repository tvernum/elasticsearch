/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.extension;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.RoleRetrievalResult;

import java.util.Set;
import java.util.function.BiConsumer;

public class TestDynamicRoleProvider implements BiConsumer<Set<String>, ActionListener<RoleRetrievalResult>> {
    public static final String ROLE_NAME = "@test";
    private final RoleDescriptor descriptor;

    public TestDynamicRoleProvider() {
        this.descriptor = new RoleDescriptor(
            ROLE_NAME,
            null,
            new RoleDescriptor.IndicesPrivileges[] {
                RoleDescriptor.IndicesPrivileges.builder().indices("test").privileges("read").build() },
            null
        );
    }

    @Override
    public void accept(Set<String> roleNames, ActionListener<RoleRetrievalResult> listener) {

        if (roleNames.contains(ROLE_NAME)) {
            listener.onResponse(RoleRetrievalResult.success(Set.of(descriptor)));
        } else {
            listener.onResponse(RoleRetrievalResult.success(Set.of()));
        }
    }
}
