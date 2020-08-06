/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.permission;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.permission.FieldPermissionsCache;
import org.elasticsearch.xpack.core.security.authz.permission.IndicesAccessDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.Permissions;
import org.elasticsearch.xpack.core.security.authz.permission.ResourcePrivilegesMap;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class RestrictedPermissions implements Permissions {
    private final Permissions delegate;
    private final Automaton restrictedClusterActions;
    private final Predicate<String> isRestrictedClusterActions;

    public RestrictedPermissions(Permissions delegate, Set<String> restrictedClusterActions) {
        this.delegate = delegate;
        this.restrictedClusterActions = Automatons.patterns(
            restrictedClusterActions.stream().map(s -> s + "*").collect(Collectors.toUnmodifiableSet()));
        this.isRestrictedClusterActions = Automatons.predicate(restrictedClusterActions);
    }

    @Override
    public String[] names() {
        return delegate.names();
    }

    @Override
    public String description() {
        return delegate.description() + " (with restrictions)";
    }

    @Override
    public Collection<ClusterPrivilege> clusterPrivileges() {
        // TODO Should this be restricted ?
        return delegate.clusterPrivileges();
    }

    @Override
    public Set<IndicesAccessDescriptor> indexPrivileges() {
        return delegate.indexPrivileges();
    }

    @Override
    public Set<RoleDescriptor.ApplicationResourcePrivileges> applicationPrivileges() {
        return delegate.applicationPrivileges();
    }

    @Override
    public Set<String> runAsPrincipals() {
        return delegate.runAsPrincipals();
    }

    @Override
    public Predicate<IndexAbstraction> allowedIndicesMatcher(String action) {
        return delegate.allowedIndicesMatcher(action);
    }

    @Override
    public Automaton allowedActionsMatcher(String index) {
        return delegate.allowedActionsMatcher(index);
    }

    @Override
    public boolean checkIndicesAction(String action) {
        return delegate.checkIndicesAction(action);
    }

    @Override
    public IndicesAccessControl authorizeIndices(String action, Set<String> requestedIndicesOrAliases,
                                                 Map<String, IndexAbstraction> aliasAndIndexLookup,
                                                 FieldPermissionsCache fieldPermissionsCache) {
        return delegate.authorizeIndices(action, requestedIndicesOrAliases, aliasAndIndexLookup, fieldPermissionsCache);
    }

    @Override
    public ResourcePrivilegesMap checkIndicesPrivileges(Set<String> checkForIndexPatterns, boolean allowRestrictedIndices,
                                                        Set<String> checkForPrivileges) {
        return delegate.checkIndicesPrivileges(checkForIndexPatterns, allowRestrictedIndices, checkForPrivileges);
    }

    @Override
    public boolean checkClusterAction(String action, TransportRequest request, Authentication authentication) {
        if (isRestrictedClusterActions.test(action)) {
            return false;
        }
        return delegate.checkClusterAction(action, request, authentication);
    }

    @Override
    public boolean grants(ClusterPrivilege clusterPrivilege) {
        // TODO : Needed for has-privileges
        return delegate.grants(clusterPrivilege);
    }

    @Override
    public boolean checkRunAs(String runAsName) {
        return delegate.checkRunAs(runAsName);
    }

    @Override
    public ResourcePrivilegesMap checkApplicationResourcePrivileges(String applicationName, Set<String> checkForResources,
                                                                    Set<String> checkForPrivilegeNames,
                                                                    Collection<ApplicationPrivilegeDescriptor> storedPrivileges) {
        return delegate.checkApplicationResourcePrivileges(applicationName, checkForResources, checkForPrivilegeNames, storedPrivileges);
    }
}
