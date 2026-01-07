/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.extension;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.authz.store.RoleRetrievalResult;
import org.elasticsearch.xpack.core.security.ext.DynamicRoleAssigner;

import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

public class TestDynamicRoleExtension implements SecurityExtension {
    @Override
    public List<DynamicRoleAssigner> getDynamicRoleAssigners(SecurityComponents components) {
        return List.of(new TestDynamicRoleAssigner());
    }

    @Override
    public List<BiConsumer<Set<String>, ActionListener<RoleRetrievalResult>>> getRolesProviders(SecurityComponents components) {
        return List.of(new TestDynamicRoleProvider());
    }
}
