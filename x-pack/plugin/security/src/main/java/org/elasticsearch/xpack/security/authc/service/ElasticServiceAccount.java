/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.service;

import org.elasticsearch.common.Strings;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.user.User;

import java.util.Map;
import java.util.Objects;

public class ElasticServiceAccount implements ServiceAccount {
    private final ServiceAccountId id;
    private final RoleDescriptor roleDescriptor;
    private final User user;

    public ElasticServiceAccount(String serviceName, RoleDescriptor roleDescriptor) {
        this.id = new ServiceAccountId("elastic", serviceName);
        this.roleDescriptor = Objects.requireNonNull(roleDescriptor, "Role descriptor cannot be null");
        if (roleDescriptor.getName().equals(id.accountName()) == false) {
            throw new IllegalArgumentException("the provided role descriptor [" + roleDescriptor.getName()
                + "] must have the same name as the service account [" + id.accountName() + "]");
        }
        this.user = new User(id.accountName(), Strings.EMPTY_ARRAY, id + " service account", null, Map.of(), true);
    }

    @Override
    public ServiceAccountId id() {
        return id;
    }

    @Override
    public RoleDescriptor role() {
        return roleDescriptor;
    }

    @Override
    public User asUser() {
        return user;
    }

}
