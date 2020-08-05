/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.Role;

import java.util.Map;
import java.util.Set;

public interface RolesStore {

    void roles(Set<String> roleNames, ActionListener<Role> roleActionListener);

    void getRoles(Authentication authentication, ActionListener<Role> roleActionListener);

    // Role retrieval methods
    void getRoleDescriptors(Set<String> roleNames, ActionListener<Set<RoleDescriptor>> listener);

    // Cache management methods
    void invalidateAll();
    void invalidate(String role);

    // Usage states
    void usageStats(ActionListener<Map<String, Object>> listener);

    class Holder {
        public final RolesStore store;

        public Holder(RolesStore store) {
            this.store = store;
        }
    }
}
