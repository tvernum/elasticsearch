/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.Permissions;

import java.util.Map;
import java.util.Set;

public interface PermissionsStore<T extends Permissions> {

    void getUserPermissions(Authentication authentication, ActionListener<? super T> roleActionListener);

    // Role retrieval methods
    void getNamedRoles(Set<String> roleNames, ActionListener<? super T> roleActionListener);
    void getRoleDescriptors(Set<String> roleNames, ActionListener<Set<RoleDescriptor>> listener);

    // Cache management methods
    void invalidateAll();
    void invalidate(String role);

    // Usage states
    void usageStats(ActionListener<Map<String, Object>> listener);

    class Holder {
        public final PermissionsStore store;

        public Holder(PermissionsStore store) {
            this.store = store;
        }
    }
}
