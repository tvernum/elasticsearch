/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.lucene.util.automaton.Automaton;
import org.apache.lucene.util.automaton.Operations;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilegeResolver;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.IndexPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.Privilege;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

public class Role implements Permissions {

    public static final Role EMPTY = Role.builder("__empty").build();

    private final String[] names;
    private final ClusterPermission cluster;
    private final IndicesPermission indices;
    private final ApplicationPermission application;
    private final RunAsPermission runAs;

    Role(String[] names, ClusterPermission cluster, IndicesPermission indices, ApplicationPermission application, RunAsPermission runAs) {
        this.names = names;
        this.cluster = Objects.requireNonNull(cluster);
        this.indices = Objects.requireNonNull(indices);
        this.application = Objects.requireNonNull(application);
        this.runAs = Objects.requireNonNull(runAs);
    }

    @Override
    public String description() {
        return Strings.arrayToCommaDelimitedString(names());
    }

    @Override
    public String[] names() {
        return names;
    }

    public ClusterPermission cluster() {
        return cluster;
    }

    public IndicesPermission indices() {
        return indices;
    }

    public ApplicationPermission application() {
        return application;
    }

    public RunAsPermission runAs() {
        return runAs;
    }

    @Override
    public Collection<ClusterPrivilege> clusterPrivileges() {
        return cluster.privileges();
    }

    @Override
    public Set<IndicesAccessDescriptor> indexPrivileges() {
        Set<IndicesAccessDescriptor> descriptors = new LinkedHashSet<>();
        for (IndicesPermission.Group group : indices.groups()) {
            final Set<BytesReference> queries = group.getQuery() == null ? Collections.emptySet() : group.getQuery();
            final Set<FieldPermissionsDefinition.FieldGrantExcludeGroup> fieldSecurity = group.getFieldPermissions().hasFieldLevelSecurity()
                ? group.getFieldPermissions().getFieldPermissionsDefinition().getFieldGrantExcludeGroups() : Collections.emptySet();
            descriptors.add(new IndicesAccessDescriptor(
                Arrays.asList(group.indices()),
                group.privilege().name(),
                fieldSecurity,
                queries,
                group.allowRestrictedIndices()
            ));
        }
        return descriptors;
    }

    @Override
    public Set<RoleDescriptor.ApplicationResourcePrivileges> applicationPrivileges() {
        Set<RoleDescriptor.ApplicationResourcePrivileges> descriptors = new LinkedHashSet<>();
        for (String applicationName : application.getApplicationNames()) {
            for (ApplicationPrivilege privilege : application.getPrivileges(applicationName)) {
                final Set<String> resources = application.getResourcePatterns(privilege);
                if (resources.isEmpty() == false) {
                    descriptors.add(RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application(applicationName)
                        .privileges(privilege.name())
                        .resources(resources)
                        .build());
                }
            }
        }
        return descriptors;
    }

    @Override
    public Set<String> runAsPrincipals() {
        final Privilege runAsPrivilege = runAs.getPrivilege();
        if (Operations.isEmpty(runAsPrivilege.getAutomaton())) {
            return Set.of();
        } else {
            return runAsPrivilege.name();
        }
    }

    public static Builder builder(String... names) {
        return new Builder(names);
    }

    public static Builder builder(RoleDescriptor rd, FieldPermissionsCache fieldPermissionsCache) {
        return new Builder(rd, fieldPermissionsCache);
    }

    @Override
    public Predicate<IndexAbstraction> allowedIndicesMatcher(String action) {
        return indices.allowedIndicesMatcher(action);
    }

    @Override
    public Automaton allowedActionsMatcher(String index) {
        return indices.allowedActionsMatcher(index);
    }

    @Override
    public boolean checkRunAs(String runAsName) {
        return runAs.check(runAsName);
    }

    @Override
    public boolean checkIndicesAction(String action) {
        return indices.check(action);
    }


    @Override
    public ResourcePrivilegesMap checkIndicesPrivileges(Set<String> checkForIndexPatterns, boolean allowRestrictedIndices,
                                                        Set<String> checkForPrivileges) {
        return indices.checkResourcePrivileges(checkForIndexPatterns, allowRestrictedIndices, checkForPrivileges);
    }

    @Override
    public boolean checkClusterAction(String action, TransportRequest request, Authentication authentication) {
        return cluster.check(action, request, authentication);
    }

    @Override
    public boolean grants(ClusterPrivilege clusterPrivilege) {
        return cluster.implies(clusterPrivilege.buildPermission(ClusterPermission.builder()).build());
    }

    @Override
    public ResourcePrivilegesMap checkApplicationResourcePrivileges(final String applicationName, Set<String> checkForResources,
                                                                    Set<String> checkForPrivilegeNames,
                                                                    Collection<ApplicationPrivilegeDescriptor> storedPrivileges) {
        return application.checkResourcePrivileges(applicationName, checkForResources, checkForPrivilegeNames, storedPrivileges);
    }

    @Override
    public IndicesAccessControl authorizeIndices(String action, Set<String> requestedIndicesOrAliases,
                                                 Map<String, IndexAbstraction> aliasAndIndexLookup,
                                                 FieldPermissionsCache fieldPermissionsCache) {
        Map<String, IndicesAccessControl.IndexAccessControl> indexPermissions = indices.authorize(
            action, requestedIndicesOrAliases, aliasAndIndexLookup, fieldPermissionsCache
        );

        // At least one role / indices permission set need to match with all the requested indices/aliases:
        boolean granted = true;
        for (Map.Entry<String, IndicesAccessControl.IndexAccessControl> entry : indexPermissions.entrySet()) {
            if (!entry.getValue().isGranted()) {
                granted = false;
                break;
            }
        }
        return new IndicesAccessControl(granted, indexPermissions);
    }

    public static class Builder {

        private final String[] names;
        private ClusterPermission cluster = ClusterPermission.NONE;
        private RunAsPermission runAs = RunAsPermission.NONE;
        private List<IndicesPermission.Group> groups = new ArrayList<>();
        private List<Tuple<ApplicationPrivilege, Set<String>>> applicationPrivs = new ArrayList<>();

        private Builder(String[] names) {
            this.names = names;
        }

        private Builder(RoleDescriptor rd, @Nullable FieldPermissionsCache fieldPermissionsCache) {
            this.names = new String[] { rd.getName() };
            cluster(Sets.newHashSet(rd.getClusterPrivileges()), Arrays.asList(rd.getConditionalClusterPrivileges()));
            groups.addAll(convertFromIndicesPrivileges(rd.getIndicesPrivileges(), fieldPermissionsCache));

            final RoleDescriptor.ApplicationResourcePrivileges[] applicationPrivileges = rd.getApplicationPrivileges();
            for (int i = 0; i < applicationPrivileges.length; i++) {
                applicationPrivs.add(convertApplicationPrivilege(rd.getName(), i, applicationPrivileges[i]));
            }

            String[] rdRunAs = rd.getRunAs();
            if (rdRunAs != null && rdRunAs.length > 0) {
                this.runAs(new Privilege(Sets.newHashSet(rdRunAs), rdRunAs));
            }
        }

        public Builder cluster(Set<String> privilegeNames, Iterable<ConfigurableClusterPrivilege> configurableClusterPrivileges) {
            ClusterPermission.Builder builder = ClusterPermission.builder();
            if (privilegeNames.isEmpty() == false) {
                for (String name : privilegeNames) {
                    builder = ClusterPrivilegeResolver.resolve(name).buildPermission(builder);
                }
            }
            for (ConfigurableClusterPrivilege ccp : configurableClusterPrivileges) {
                builder = ccp.buildPermission(builder);
            }
            this.cluster = builder.build();
            return this;
        }

        public Builder runAs(Privilege privilege) {
            runAs = new RunAsPermission(privilege);
            return this;
        }

        public Builder add(IndexPrivilege privilege, String... indices) {
            groups.add(new IndicesPermission.Group(privilege, FieldPermissions.DEFAULT, null, false, indices));
            return this;
        }

        public Builder add(FieldPermissions fieldPermissions, Set<BytesReference> query, IndexPrivilege privilege,
                boolean allowRestrictedIndices, String... indices) {
            groups.add(new IndicesPermission.Group(privilege, fieldPermissions, query, allowRestrictedIndices, indices));
            return this;
        }

        public Builder addApplicationPrivilege(ApplicationPrivilege privilege, Set<String> resources) {
            applicationPrivs.add(new Tuple<>(privilege, resources));
            return this;
        }

        public Role build() {
            IndicesPermission indices = groups.isEmpty() ? IndicesPermission.NONE :
                new IndicesPermission(groups.toArray(new IndicesPermission.Group[groups.size()]));
            final ApplicationPermission applicationPermission
                = applicationPrivs.isEmpty() ? ApplicationPermission.NONE : new ApplicationPermission(applicationPrivs);
            return new Role(names, cluster, indices, applicationPermission, runAs);
        }

        static List<IndicesPermission.Group> convertFromIndicesPrivileges(RoleDescriptor.IndicesPrivileges[] indicesPrivileges,
                                                                          @Nullable FieldPermissionsCache fieldPermissionsCache) {
            List<IndicesPermission.Group> list = new ArrayList<>(indicesPrivileges.length);
            for (RoleDescriptor.IndicesPrivileges privilege : indicesPrivileges) {
                final FieldPermissions fieldPermissions;
                if (fieldPermissionsCache != null) {
                    fieldPermissions = fieldPermissionsCache.getFieldPermissions(privilege.getGrantedFields(), privilege.getDeniedFields());
                } else {
                    fieldPermissions = new FieldPermissions(
                        new FieldPermissionsDefinition(privilege.getGrantedFields(), privilege.getDeniedFields()));
                }
                final Set<BytesReference> query = privilege.getQuery() == null ? null : Collections.singleton(privilege.getQuery());
                list.add(new IndicesPermission.Group(IndexPrivilege.get(Sets.newHashSet(privilege.getPrivileges())), fieldPermissions,
                        query, privilege.allowRestrictedIndices(), privilege.getIndices()));
            }
            return list;
        }

        static Tuple<ApplicationPrivilege, Set<String>> convertApplicationPrivilege(String role, int index,
                                                                                    RoleDescriptor.ApplicationResourcePrivileges arp) {
            return new Tuple<>(new ApplicationPrivilege(arp.getApplication(),
                Sets.newHashSet(arp.getPrivileges()),
                arp.getPrivileges()
            ), Sets.newHashSet(arp.getResources()));
        }
    }

}
