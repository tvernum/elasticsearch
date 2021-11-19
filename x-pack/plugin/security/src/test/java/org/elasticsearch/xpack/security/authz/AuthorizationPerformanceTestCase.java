/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.Version;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.esnative.NativeRealmSettings;
import org.elasticsearch.xpack.core.security.authz.AuthorizationEngine;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.FieldPermissionsCache;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.support.Automatons;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;
import org.mockito.Mockito;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthorizationPerformanceTestCase extends ESTestCase {

    protected Tuple<TimeValue, Set<String>> lodAuthorizedIndices(
        Map<String, IndexAbstraction> lookup,
        User user,
        RoleDescriptor roleDescriptor
    ) {
        final CompositeRolesStore rolesStore = Mockito.mock(CompositeRolesStore.class);
        final RBACEngine engine = new RBACEngine(Settings.EMPTY, rolesStore);

        Authentication.RealmRef realm = new Authentication.RealmRef("realm", NativeRealmSettings.TYPE, "node01");
        Authentication authc = new Authentication(user, realm, realm);
        TransportRequest searchRequest = new SearchRequest("*");
        AuthorizationEngine.RequestInfo reqInfo = new AuthorizationEngine.RequestInfo(authc, searchRequest, SearchAction.NAME, null);
        FieldPermissionsCache fieldPermissionsCache = new FieldPermissionsCache(Settings.EMPTY);
        Automaton restrictedIndicesAutomaton = Automatons.patterns(".security", ".security-7");
        Role role = Role.builder(roleDescriptor, fieldPermissionsCache, restrictedIndicesAutomaton).build();
        AuthorizationEngine.AuthorizationInfo authz = new RBACEngine.RBACAuthorizationInfo(role, role);

        PlainActionFuture<Set<String>> future = new PlainActionFuture<>();

        final long start = System.nanoTime();
        engine.loadAuthorizedIndices(reqInfo, authz, lookup, future);
        final long end = System.nanoTime();

        Tuple<TimeValue, Set<String>> result = new Tuple<>(TimeValue.timeValueNanos(end - start), future.actionGet());
        return result;
    }

    /**
     * @param inputAliasJson The "alias.json" for the cluster to simulate (from {@code GET /_alias})
     */
    protected Map<String, IndexAbstraction> buildIndexLookup(InputStream inputAliasJson) {
        final Map<String, IndexAbstraction> lookup = new HashMap<>();
        Map<String, Set<String>> result = readIndicesAndAliases(inputAliasJson);
        final Map<String, Set<String>> indices = result;
        final Map<AliasMetadata, List<IndexMetadata>> aliases = new HashMap<>();
        indices.forEach((index, indexAliases) -> {
            Set<AliasMetadata> aliasMetadata = indexAliases.stream().map(this::aliasMetadata).collect(Collectors.toSet());
            IndexMetadata metadata = indexMetadata(index, aliasMetadata);
            lookup.put(index, new IndexAbstraction.ConcreteIndex(metadata));
            for (AliasMetadata alias : aliasMetadata) {
                aliases.computeIfAbsent(alias, key -> new ArrayList<>()).add(metadata);
            }
        });
        aliases.forEach((alias, indexMetadata) -> { lookup.put(alias.alias(), new IndexAbstraction.Alias(alias, indexMetadata)); });
        return lookup;
    }

    private AliasMetadata aliasMetadata(String alias) {
        return AliasMetadata.builder(alias).build();
    }

    private IndexMetadata indexMetadata(String index, Set<AliasMetadata> aliases) {
        final IndexMetadata.Builder builder = IndexMetadata.builder(index);
        aliases.forEach(builder::putAlias);
        builder.settings(
            Settings.builder()
                .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
                .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
        );
        return builder.build();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Set<String>> readIndicesAndAliases(InputStream in) {
        Map<String, Set<String>> result = new HashMap<>();
        final Map<String, Object> indexNames = XContentHelper.convertToMap(XContentType.JSON.xContent(), in, false);
        indexNames.forEach((index, data) -> {
            assert data instanceof Map;
            final Object aliases = ((Map<String, Object>) data).get("aliases");
            if (aliases == null) {
                result.put(index, Set.of());
            } else {
                assert aliases instanceof Map;
                result.put(index, ((Map<String, ?>) aliases).keySet());
            }
        });
        return result;
    }
}
