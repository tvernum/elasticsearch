/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.settings.ClusterUpdateSettingsAction;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.file.FileRealmSettings;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.Permissions;
import org.elasticsearch.xpack.security.authz.permission.RestrictedPermissions;

import java.util.Map;
import java.util.Set;

public class FilteringPermissionsStore implements PermissionsStore<Permissions> {

    private final PermissionsStore<?> delegate;
    private final XPackLicenseState licenseState;

    public FilteringPermissionsStore(Settings settings,
                                     PermissionsStore<?> delegate,
                                     ResourceWatcherService resourceWatcherService,
                                     XPackLicenseState licenseState) {

        this.delegate = delegate;
        this.licenseState = licenseState;
    }

    private Set<String> getRestrictedClusterActions(Authentication authentication) {
        if (authentication.getAuthenticationType() == Authentication.AuthenticationType.REALM
            && authentication.getAuthenticatedBy().getType().equals(FileRealmSettings.TYPE)) {
            return Set.of();
        } else {
            return Set.of(ClusterUpdateSettingsAction.NAME);
        }
    }

    @Override
    public void getUserPermissions(Authentication authentication, ActionListener<? super Permissions> roleActionListener) {
        final Set<String> restrictedActions = getRestrictedClusterActions(authentication);
        delegate.getUserPermissions(authentication, ActionListener.wrap(
            userRole -> roleActionListener.onResponse(restrictedActions.isEmpty() ? userRole : new RestrictedPermissions(userRole, restrictedActions)),
            roleActionListener::onFailure));
    }

    @Override
    public void getNamedRoles(Set<String> roleNames, ActionListener<? super Permissions> roleActionListener) {
        delegate.getNamedRoles(roleNames, roleActionListener);
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
