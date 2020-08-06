/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action.user;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.IndicesAccessDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivileges;

import java.io.IOException;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Response for a {@link GetUserPrivilegesRequest}
 */
public final class GetUserPrivilegesResponse extends ActionResponse {

    private Set<String> cluster;
    private Set<ConfigurableClusterPrivilege> configurableClusterPrivileges;
    private Set<IndicesAccessDescriptor> index;
    private Set<RoleDescriptor.ApplicationResourcePrivileges> application;
    private Set<String> runAs;

    public GetUserPrivilegesResponse(StreamInput in) throws IOException {
        super(in);
        cluster = Collections.unmodifiableSet(in.readSet(StreamInput::readString));
        configurableClusterPrivileges = Collections.unmodifiableSet(in.readSet(ConfigurableClusterPrivileges.READER));
        index = Collections.unmodifiableSet(in.readSet(IndicesAccessDescriptor::new));
        application = Collections.unmodifiableSet(in.readSet(RoleDescriptor.ApplicationResourcePrivileges::new));
        runAs = Collections.unmodifiableSet(in.readSet(StreamInput::readString));
    }

    public GetUserPrivilegesResponse(Set<String> cluster, Set<ConfigurableClusterPrivilege> conditionalCluster,
                                     Set<IndicesAccessDescriptor> index,
                                     Set<RoleDescriptor.ApplicationResourcePrivileges> application,
                                     Set<String> runAs) {
        this.cluster = Collections.unmodifiableSet(cluster);
        this.configurableClusterPrivileges = Collections.unmodifiableSet(conditionalCluster);
        this.index = Collections.unmodifiableSet(index);
        this.application = Collections.unmodifiableSet(application);
        this.runAs = Collections.unmodifiableSet(runAs);
    }

    public Set<String> getClusterPrivileges() {
        return cluster;
    }

    public Set<ConfigurableClusterPrivilege> getConditionalClusterPrivileges() {
        return configurableClusterPrivileges;
    }

    public Set<IndicesAccessDescriptor> getIndexPrivileges() {
        return index;
    }

    public Set<RoleDescriptor.ApplicationResourcePrivileges> getApplicationPrivileges() {
        return application;
    }

    public Set<String> getRunAs() {
        return runAs;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(cluster, StreamOutput::writeString);
        out.writeCollection(configurableClusterPrivileges, ConfigurableClusterPrivileges.WRITER);
        out.writeCollection(index);
        out.writeCollection(application);
        out.writeCollection(runAs, StreamOutput::writeString);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        final GetUserPrivilegesResponse that = (GetUserPrivilegesResponse) other;
        return Objects.equals(cluster, that.cluster) &&
            Objects.equals(configurableClusterPrivileges, that.configurableClusterPrivileges) &&
            Objects.equals(index, that.index) &&
            Objects.equals(application, that.application) &&
            Objects.equals(runAs, that.runAs);
    }

    @Override
    public int hashCode() {
        return Objects.hash(cluster, configurableClusterPrivileges, index, application, runAs);
    }

}
