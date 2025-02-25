/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.TransportVersion;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.common.util.CachedSupplier;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptorsIntersection;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.permission.ApplicationPermission;
import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;
import org.elasticsearch.xpack.core.security.authz.permission.FieldPermissionsCache;
import org.elasticsearch.xpack.core.security.authz.permission.IndicesPermission;
import org.elasticsearch.xpack.core.security.authz.permission.RemoteClusterPermissions;
import org.elasticsearch.xpack.core.security.authz.permission.RemoteIndicesPermission;
import org.elasticsearch.xpack.core.security.authz.permission.ResourcePrivilegesMap;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.permission.RunAsPermission;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.IndexPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;
import org.elasticsearch.xpack.core.security.support.StringMatcher;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class IndexRestrictedRole implements Role {

    private final Logger logger = LogManager.getLogger(IndexRestrictedRole.class);

    private static final BiPredicate<String, IndexAbstraction> INDEX_PREDICATE_ALWAYS_TRUE = (index, abstraction) -> true;

    public static final class IndexAccessLimit {

        private final StringMatcher indexMatcher;
        private final Supplier<Automaton> indexAutomaton;
        private final String[] indexNames;
        private final IndexPrivilege allowedPrivilege;

        public IndexAccessLimit(String[] indexNames, IndexPrivilege allowedPrivilege) {
            this.indexNames = indexNames;
            this.indexMatcher = StringMatcher.of(indexNames);
            this.indexAutomaton = CachedSupplier.wrap(() -> Automatons.patterns(indexNames));
            this.allowedPrivilege = allowedPrivilege;
        }

        public String[] indexNames() {
            return indexNames;
        }

        public IndexPrivilege allowedPrivilege() {
            return allowedPrivilege;
        }

        public IndicesPermission.IsResourceAuthorizedPredicate limitIndices(
            String action,
            IndicesPermission.IsResourceAuthorizedPredicate resourcePredicate
        ) {
            if (allowedPrivilege.predicate().test(action)) {
                // This action is not restricted so, we don't care about the index name
                return resourcePredicate;
            } else {
                // TODO handle the abstraction correctly
                return resourcePredicate.and((index, abstraction) -> indexMatcher.test(index) == false);
            }
        }

        public Automaton limitActions(String index, Automaton automaton) {
            if (indexMatcher.test(index)) {
                // This index is restricted, intersect the automaton
                return Automatons.intersectAndMinimize(automaton, this.allowedPrivilege.getAutomaton());
            } else {
                return automaton;
            }
        }
    }

    private final String[] restrictionNames;
    private final String[] names;
    private final Role baseRole;
    private final List<IndexAccessLimit> limits;

    public IndexRestrictedRole(String[] restrictionNames, Role baseRole, List<IndexAccessLimit> limits) {
        this.restrictionNames = restrictionNames;
        this.baseRole = baseRole;
        this.limits = limits;
        this.names = Stream.concat(Arrays.stream(baseRole.names()), Arrays.stream(restrictionNames).map(n -> "@restricted_by:" + n))
            .toArray(String[]::new);
    }

    @Override
    public String[] names() {
        return names;
    }

    @Override
    public ClusterPermission cluster() {
        return baseRole.cluster();
    }

    @Override
    public IndicesPermission indices() {
        /*
         TODO: Should we report the restrictions, and if so how?
         We have 3 options:
          1. Just `return baseRole.indices()` which hides the restrictions, but so does operator privileges
             so maybe it's OK if IndexLimits are treated the same way as operator privileges are
          2. Throw an exception like `LimitedRole` does, which means GetUserPrivileges fails
          3. Try to synthesise the actual privileges. This is not possible in all cases, but we might be able to do a
             good enough in some cases
             (the hard part is converting an index pattern of "foo-*" to "foo-* except foo-readonly")
         */
        return baseRole.indices();
    }

    @Override
    public IndicesPermission.IsResourceAuthorizedPredicate allowedIndicesMatcher(String action) {
        IndicesPermission.IsResourceAuthorizedPredicate predicate = baseRole.allowedIndicesMatcher(action);
        for (var limit : limits) {
            predicate = limit.limitIndices(action, predicate);
        }
        return predicate;
    }

    @Override
    public Automaton allowedActionsMatcher(String index) {
        Automaton automaton = baseRole.allowedActionsMatcher(index);
        for (var limit : limits) {
            automaton = limit.limitActions(index, automaton);
        }
        return automaton;
    }

    @Override
    public boolean checkIndicesAction(String action) {
        return baseRole.checkIndicesAction(action);
    }

    @Override
    public boolean checkIndicesPrivileges(
        Set<String> checkForIndexPatterns,
        boolean allowRestrictedIndices,
        Set<String> checkForPrivileges,
        ResourcePrivilegesMap.Builder resourcePrivilegesMapBuilder
    ) {
        boolean allAllowed = baseRole.checkIndicesPrivileges(
            checkForIndexPatterns,
            allowRestrictedIndices,
            checkForPrivileges,
            resourcePrivilegesMapBuilder
        );
        if (false == allAllowed && null == resourcePrivilegesMapBuilder) {
            // short-circuit only if not interested in the detailed individual check results
            return false;
        }

        for (String forIndexPattern : checkForIndexPatterns) {
            for (var limit : limits) {
                Automaton checkIndexAutomaton = Automatons.patterns(forIndexPattern);
                // TODO handle restricted indices here ?
                if (Automatons.subsetOf(checkIndexAutomaton, limit.indexAutomaton.get())) {
                    // This index is restricted
                    for (String privilege : checkForPrivileges) {
                        IndexPrivilege indexPrivilege = IndexPrivilege.get(Collections.singleton(privilege));
                        if (Automatons.subsetOf(indexPrivilege.getAutomaton(), limit.allowedPrivilege.getAutomaton()) == false) {
                            // The restriction does not allow this privilege
                            logger.debug("Index restrictions prevent [{}] access to [{}]", privilege, forIndexPattern);
                            allAllowed = false;
                            if (resourcePrivilegesMapBuilder == null) {
                                return false;
                            } else {
                                resourcePrivilegesMapBuilder.addResourcePrivilege(forIndexPattern, privilege, Boolean.FALSE);
                            }
                        }
                    }
                }
            }
        }

        return allAllowed;
    }

    @Override
    public IndicesAccessControl authorize(
        String action,
        Set<String> requestedIndicesOrAliases,
        Metadata metadata,
        FieldPermissionsCache fieldPermissionsCache
    ) {
        final IndicesAccessControl indicesAccessControl = baseRole.authorize(
            action,
            requestedIndicesOrAliases,
            metadata,
            fieldPermissionsCache
        );

        if (indicesAccessControl.isGranted() == false) {
            return indicesAccessControl;
        }

        final List<IndexAccessLimit> actionLimits = this.limits.stream()
            .filter(l -> l.allowedPrivilege.predicate().test(action) == false)
            .toList();

        if (actionLimits.isEmpty()) {
            return indicesAccessControl;
        }

        boolean allGranted = true;
        final Set<String> restrictedResources = Sets.newHashSetWithExpectedSize(requestedIndicesOrAliases.size());
        for (var limit : limits) {
            if (limit.allowedPrivilege.predicate().test(action) == false) {
                // This privilege is restricted
                boolean matchResources = true;
                for (String index : requestedIndicesOrAliases) {
                    // TODO use actual metadata resources
                    if (limit.indexMatcher.test(index)) {
                        // this index is restricted
                        allGranted = false;
                        restrictedResources.add(index);
                    }
                }
            }
        }

        final IndicesAccessControl limitedByIndicesAccessControl = new IndicesAccessControl(
            allGranted,
            requestedIndicesOrAliases.stream()
                .filter(idx -> restrictedResources.contains(idx) == false)
                .collect(Collectors.toMap(Function.identity(), ignore -> IndicesAccessControl.IndexAccessControl.ALLOW_ALL))
        );
        return indicesAccessControl.limitIndicesAccessControl(limitedByIndicesAccessControl);
    }

    @Override
    public ApplicationPermission application() {
        return baseRole.application();
    }

    @Override
    public RunAsPermission runAs() {
        return baseRole.runAs();
    }

    @Override
    public RemoteIndicesPermission remoteIndices() {
        return baseRole.remoteIndices();
    }

    @Override
    public RemoteClusterPermissions remoteCluster() {
        return baseRole.remoteCluster();
    }

    @Override
    public boolean hasWorkflowsRestriction() {
        return baseRole.hasWorkflowsRestriction();
    }

    @Override
    public Role forWorkflow(String workflow) {
        Role r = baseRole.forWorkflow(workflow);
        if (r == EMPTY_RESTRICTED_BY_WORKFLOW) {
            return EMPTY;
        }
        if (r == baseRole) {
            return this;
        } else {
            return new IndexRestrictedRole(this.restrictionNames, r, limits);
        }
    }

    @Override
    public boolean hasFieldOrDocumentLevelSecurity() {
        return baseRole.hasFieldOrDocumentLevelSecurity();
    }

    @Override
    public boolean checkRunAs(String runAsName) {
        return baseRole.checkRunAs(runAsName);
    }

    @Override
    public boolean checkClusterAction(String action, TransportRequest request, Authentication authentication) {
        return baseRole.checkClusterAction(action, request, authentication);
    }

    @Override
    public boolean grants(ClusterPrivilege clusterPrivilege) {
        return false;
    }

    @Override
    public boolean checkApplicationResourcePrivileges(
        String applicationName,
        Set<String> checkForResources,
        Set<String> checkForPrivilegeNames,
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges,
        ResourcePrivilegesMap.Builder resourcePrivilegesMapBuilder
    ) {
        return baseRole.checkApplicationResourcePrivileges(
            applicationName,
            checkForResources,
            checkForPrivilegeNames,
            storedPrivileges,
            resourcePrivilegesMapBuilder
        );
    }

    @Override
    public RoleDescriptorsIntersection getRoleDescriptorsIntersectionForRemoteCluster(
        String remoteClusterAlias,
        TransportVersion remoteClusterVersion
    ) {
        return baseRole.getRoleDescriptorsIntersectionForRemoteCluster(remoteClusterAlias, remoteClusterVersion);
    }
}
