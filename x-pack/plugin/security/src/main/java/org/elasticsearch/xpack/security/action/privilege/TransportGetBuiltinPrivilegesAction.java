/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.action.privilege;

import org.apache.lucene.util.automaton.Automaton;
import org.apache.lucene.util.automaton.Operations;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.action.privilege.GetBuiltinPrivilegesAction;
import org.elasticsearch.xpack.core.security.action.privilege.GetBuiltinPrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.privilege.GetBuiltinPrivilegesResponse;
import org.elasticsearch.xpack.core.security.action.privilege.GetBuiltinPrivilegesResponse.PrivilegeInfo;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilegeResolver;
import org.elasticsearch.xpack.core.security.authz.privilege.IndexPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.NamedClusterPrivilege;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Transport action to retrieve one or more application privileges from the security index
 */
public class TransportGetBuiltinPrivilegesAction extends HandledTransportAction<GetBuiltinPrivilegesRequest, GetBuiltinPrivilegesResponse> {

    @Inject
    public TransportGetBuiltinPrivilegesAction(ActionFilters actionFilters, TransportService transportService) {
        super(GetBuiltinPrivilegesAction.NAME, transportService, actionFilters, GetBuiltinPrivilegesRequest::new);
    }

    @Override
    protected void doExecute(Task task, GetBuiltinPrivilegesRequest request, ActionListener<GetBuiltinPrivilegesResponse> listener) {
        final GetBuiltinPrivilegesResponse response = getResponse(request.getFormat());
        listener.onResponse(response);
    }

    private GetBuiltinPrivilegesResponse getResponse(GetBuiltinPrivilegesRequest.Format format) {
        final TreeSet<String> clusterNames = new TreeSet<>(ClusterPrivilegeResolver.names());
        final TreeSet<String> indexNames = new TreeSet<>(IndexPrivilege.names());

        final PrivilegeInfo[] cluster = new PrivilegeInfo[clusterNames.size()];
        int i = 0;
        for (String name : clusterNames) {
            final String[] implies;
            if (format.equals(GetBuiltinPrivilegesRequest.Format.TREE)) {
                implies = calculateImplies(ClusterPrivilegeResolver.resolve(name), clusterNames);
            } else {
                implies = Strings.EMPTY_ARRAY;
            }
            cluster[i] = new PrivilegeInfo(name, implies);
            i++;
        }

        final PrivilegeInfo[] index = new PrivilegeInfo[indexNames.size()];
        i = 0;
        for (String name : indexNames) {
            final String[] implies;
            if (format.equals(GetBuiltinPrivilegesRequest.Format.TREE)) {
                implies = calculateImplies(IndexPrivilege.get(Set.of(name)), indexNames);
            } else {
                implies = Strings.EMPTY_ARRAY;
            }
            index[i] = new PrivilegeInfo(name, implies);
            i++;
        }
        return new GetBuiltinPrivilegesResponse(cluster, index);
    }

    private String[] calculateImplies(NamedClusterPrivilege privilege, Collection<String> names) {
        final List<String> implies = new ArrayList<>();
        for (String name : names) {
            if (privilege.name().equals(name)) {
                continue;
            }
            final NamedClusterPrivilege other = ClusterPrivilegeResolver.resolve(name);
            if (other == ClusterPrivilegeResolver.NONE) {
                continue;
            }
            if (privilege.permission().implies(other.permission())) {
                implies.add(name);
            }
        }
        return implies.toArray(String[]::new);
    }

    private String[] calculateImplies(IndexPrivilege privilege, Collection<String> names) {
        final List<String> implies = new ArrayList<>();
        final Automaton automaton = privilege.getAutomaton();
        for (String name : names) {
            if (privilege.name().contains(name)) {
                continue;
            }
            final IndexPrivilege other = IndexPrivilege.get(Set.of(name));
            if (other == IndexPrivilege.NONE) {
                continue;
            }
            if (Operations.subsetOf(other.getAutomaton(), automaton)) {
                implies.add(name);
            }
        }
        return implies.toArray(String[]::new);
    }

}
