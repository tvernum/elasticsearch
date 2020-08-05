/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.LimitedRole;
import org.elasticsearch.xpack.core.security.authz.permission.Role;

import java.util.Map;
import java.util.Set;

public class FilteringRolesStore implements RolesStore {

    private final RolesStore delegate;
    private final XPackLicenseState licenseState;

    public FilteringRolesStore(Settings settings,
                               RolesStore delegate,
                               ResourceWatcherService resourceWatcherService,
                               XPackLicenseState licenseState) {

        this.delegate = delegate;
        this.licenseState = licenseState;
    }

    private Set<String> getLimitingRoleNames(Authentication authentication) {
        return Set.of("admin");
    }

    @Override
    public void getRoles(Authentication authentication, ActionListener<Role> roleActionListener) {
        final Set<String> limitingRoles = getLimitingRoleNames(authentication);
        delegate.roles(limitingRoles, ActionListener.wrap(
            limitingRole -> delegate.getRoles(authentication, ActionListener.wrap(
                userRole -> roleActionListener.onResponse(LimitedRole.createLimitedRole(userRole, limitingRole)),
                roleActionListener::onFailure)),
            roleActionListener::onFailure));
    }

    @Override
    public void roles(Set<String> roleNames, ActionListener<Role> roleActionListener) {
        delegate.roles(roleNames, roleActionListener);
    }

    @Override
    public void getRoleDescriptors(Set<String> roleNames, ActionListener<Set<RoleDescriptor>> listener) {
        delegate.getRoleDescriptors(roleNames, listener);
    }

    @Override
    public void invalidateAll() {
        delegate.invalidateAll();
    }

    @Override
    public void invalidate(String role) {
        delegate.invalidate(role);
    }

    @Override
    public void usageStats(ActionListener<Map<String, Object>> listener) {
        delegate.usageStats(listener);
    }
}
