/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action.role;

import org.elasticsearch.Version;
import org.elasticsearch.action.support.nodes.BaseNodeRequest;
import org.elasticsearch.action.support.nodes.BaseNodesRequest;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilege;

import java.io.IOException;

/**
 * The request used to clear the cache for native roles stored in an index.
 * By default, all roles are cleared from the cache, but this can be restricted in two ways:
 * <ol>
 * <li>By role name</li>
 * <li>To those roles that make use of specific {@link ApplicationPrivilege application privileges}</li>
 * </ol>
 */
public class ClearRolesCacheRequest extends BaseNodesRequest<ClearRolesCacheRequest> {

    String[] names;
    String[] applications;

    /**
     * Sets the roles for which caches will be evicted. When not set all the roles will be evicted from the cache.
     *
     * @param names The role names
     */
    public ClearRolesCacheRequest names(String... names) {
        this.names = names;
        return this;
    }

    /**
     * Sets the {@link ApplicationPrivilege#getApplication() application names} for which caches will be evicted.
     *
     * @param applications Th
     */
    public ClearRolesCacheRequest applications(String... applications) {
        this.applications = applications;
        return this;
    }

    /**
     * @return an array of role names that will have the cache evicted or <code>null</code> if all
     */
    public String[] names() {
        return names;
    }

    /**
     * @return an array of {@link ApplicationPrivilege#getApplication() application names} that will have the cache evicted or
     * <code>null</code> if all roles for applications should be refreshed
     */
    public String[] applications() {
        return applications;
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        names = in.readOptionalStringArray();
        if (in.getVersion().onOrAfter(Version.V_7_0_0_alpha1)) {
            applications = in.readOptionalStringArray();
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalStringArray(names);
        if (out.getVersion().onOrAfter(Version.V_7_0_0_alpha1)) {
            out.writeOptionalStringArray(applications);
        }
    }

    public static class Node extends BaseNodeRequest {
        private String[] names;
        private String[] applications;

        public Node() {
        }

        public Node(ClearRolesCacheRequest request, String nodeId) {
            super(nodeId);
            this.names = request.names();
            this.applications = request.applications();
        }

        public String[] getNames() {
            return names;
        }

        public String[] getApplications() {
            return applications;
        }

        @Override
        public void readFrom(StreamInput in) throws IOException {
            super.readFrom(in);
            names = in.readOptionalStringArray();
            if (in.getVersion().onOrAfter(Version.V_7_0_0_alpha1)) {
                applications = in.readOptionalStringArray();
            }
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeOptionalStringArray(names);
            if (out.getVersion().onOrAfter(Version.V_7_0_0_alpha1)) {
                out.writeOptionalStringArray(applications);
            }
        }
    }
}
