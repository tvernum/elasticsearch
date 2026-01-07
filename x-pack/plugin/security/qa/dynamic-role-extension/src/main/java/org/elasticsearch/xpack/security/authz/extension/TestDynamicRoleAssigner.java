/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.authz.extension;

import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.ext.DynamicRoleAssigner;
import org.elasticsearch.xpack.core.security.support.StringMatcher;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Stream;

public class TestDynamicRoleAssigner implements DynamicRoleAssigner {

    @Override
    public Set<String> additionalRoles(Collection<RoleDescriptor> primaryRoles) {
        if (primaryRoles.stream().anyMatch(TestDynamicRoleAssigner::hasTestApplicationPrivilege)) {
            return Set.of(TestDynamicRoleProvider.ROLE_NAME);
        } else {
            return Set.of();
        }

    }

    private static boolean hasTestApplicationPrivilege(RoleDescriptor rd) {
        return Stream.of(rd.getApplicationPrivileges()).anyMatch(ap -> StringMatcher.of(ap.getApplication()).test("test"));
    }
}
