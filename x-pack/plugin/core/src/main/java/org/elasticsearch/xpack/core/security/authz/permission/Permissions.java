/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

public interface Permissions {

    String[] names();
    String description();

    Collection<ClusterPrivilege> clusterPrivileges();
    Set<IndicesAccessDescriptor> indexPrivileges();
    Set<RoleDescriptor.ApplicationResourcePrivileges> applicationPrivileges();
    Set<String> runAsPrincipals();

    /**
     * @return A predicate that will match all the indices that this role
     * has the privilege for executing the given action on.
     */
    Predicate<IndexAbstraction> allowedIndicesMatcher(String action);

    Automaton allowedActionsMatcher(String index);

    /**
     * Check if indices permissions allow for the given action
     *
     * @param action indices action
     * @return {@code true} if action is allowed else returns {@code false}
     */
    boolean checkIndicesAction(String action);

    /**
     * Returns whether at least one group encapsulated by this indices permissions is authorized to execute the
     * specified action with the requested indices/aliases. At the same time if field and/or document level security
     * is configured for any group also the allowed fields and role queries are resolved.
     */
    IndicesAccessControl authorizeIndices(String action, Set<String> requestedIndicesOrAliases,
                                          Map<String, IndexAbstraction> aliasAndIndexLookup,
                                          FieldPermissionsCache fieldPermissionsCache);

    /**
     * For given index patterns and index privileges determines allowed privileges and creates an instance of {@link ResourcePrivilegesMap}
     * holding a map of resource to {@link ResourcePrivileges} where resource is index pattern and the map of index privilege to whether it
     * is allowed or not.
     *
     * @param checkForIndexPatterns check permission grants for the set of index patterns
     * @param allowRestrictedIndices if {@code true} then checks permission grants even for restricted indices by index matching
     * @param checkForPrivileges check permission grants for the set of index privileges
     * @return an instance of {@link ResourcePrivilegesMap}
     */
    ResourcePrivilegesMap checkIndicesPrivileges(Set<String> checkForIndexPatterns, boolean allowRestrictedIndices,
                                                 Set<String> checkForPrivileges);

    /**
     * Check if cluster permissions allow for the given action in the context of given
     * authentication.
     *
     * @param action cluster action
     * @param request {@link TransportRequest}
     * @param authentication {@link Authentication}
     * @return {@code true} if action is allowed else returns {@code false}
     */
    boolean checkClusterAction(String action, TransportRequest request, Authentication authentication);

    /**
     * Check if cluster permissions grants the given cluster privilege
     *
     * @param clusterPrivilege cluster privilege
     * @return {@code true} if cluster privilege is allowed else returns {@code false}
     */
    boolean grants(ClusterPrivilege clusterPrivilege);

    boolean checkRunAs(String runAsName);

    /**
     * For a given application, checks for the privileges for resources and returns an instance of {@link ResourcePrivilegesMap} holding a
     * map of resource to {@link ResourcePrivileges} where the resource is application resource and the map of application privilege to
     * whether it is allowed or not.
     *
     * @param applicationName checks privileges for the provided application name
     * @param checkForResources check permission grants for the set of resources
     * @param checkForPrivilegeNames check permission grants for the set of privilege names
     * @param storedPrivileges stored {@link ApplicationPrivilegeDescriptor} for an application against which the access checks are
     * performed
     * @return an instance of {@link ResourcePrivilegesMap}
     */
    ResourcePrivilegesMap checkApplicationResourcePrivileges(String applicationName, Set<String> checkForResources,
                                                             Set<String> checkForPrivilegeNames,
                                                             Collection<ApplicationPrivilegeDescriptor> storedPrivileges);

}
