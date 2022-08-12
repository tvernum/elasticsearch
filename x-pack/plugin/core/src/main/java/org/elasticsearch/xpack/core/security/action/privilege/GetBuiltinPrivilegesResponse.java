/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.security.action.privilege;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Response containing one or more application privileges retrieved from the security index
 */
public final class GetBuiltinPrivilegesResponse extends ActionResponse {

    private static final String[] EMPTY_CHILDREN = new String[0];

    public record PrivilegeInfo(String name, String[] implies) {
        public PrivilegeInfo {
            Objects.requireNonNull(name);
            Objects.requireNonNull(implies);
        }
    }

    private PrivilegeInfo[] clusterPrivileges;
    private PrivilegeInfo[] indexPrivileges;

    public GetBuiltinPrivilegesResponse(PrivilegeInfo[] clusterPrivileges, PrivilegeInfo[] indexPrivileges) {
        this.clusterPrivileges = Objects.requireNonNull(clusterPrivileges, "Cluster privileges cannot be null");
        this.indexPrivileges = Objects.requireNonNull(indexPrivileges, "Index privileges cannot be null");
    }

    public GetBuiltinPrivilegesResponse(String[] clusterPrivileges, String[] indexPrivileges) {
        this.clusterPrivileges = convert(Objects.requireNonNull(clusterPrivileges, "Cluster privileges cannot be null"));
        this.indexPrivileges = convert(Objects.requireNonNull(indexPrivileges, "Index privileges cannot be null"));
    }

    private PrivilegeInfo[] convert(String[] names) {
        return Stream.of(Objects.requireNonNull(names, "Cluster privileges cannot be null"))
            .map(n -> new PrivilegeInfo(n, EMPTY_CHILDREN))
            .toArray(PrivilegeInfo[]::new);
    }

    public GetBuiltinPrivilegesResponse(Collection<String> clusterPrivileges, Collection<String> indexPrivileges) {
        this(clusterPrivileges.toArray(Strings.EMPTY_ARRAY), indexPrivileges.toArray(Strings.EMPTY_ARRAY));
    }

    public GetBuiltinPrivilegesResponse() {
        this(Collections.emptySet(), Collections.emptySet());
    }

    public GetBuiltinPrivilegesResponse(StreamInput in) throws IOException {
        super(in);
        if (in.getVersion().before(Version.V_8_4_0)) {
            this.clusterPrivileges = convert(in.readStringArray());
            this.indexPrivileges = convert(in.readStringArray());
        } else {
            this.clusterPrivileges = readPrivilegeArray(in);
            this.indexPrivileges = readPrivilegeArray(in);
        }
    }

    public PrivilegeInfo[] getClusterPrivileges() {
        return clusterPrivileges;
    }

    public PrivilegeInfo[] getIndexPrivileges() {
        return indexPrivileges;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        if (out.getVersion().before(Version.V_8_4_0)) {
            out.writeStringArray(toStringArray(clusterPrivileges));
            out.writeStringArray(toStringArray(indexPrivileges));
        } else {
            writePrivilegeArray(out, clusterPrivileges);
            writePrivilegeArray(out, indexPrivileges);
        }
    }

    private PrivilegeInfo[] readPrivilegeArray(StreamInput in) throws IOException {
        return in.readArray(this::readPrivilegeInfo, PrivilegeInfo[]::new);
    }

    private void writePrivilegeArray(StreamOutput out, PrivilegeInfo[] privileges) throws IOException {
        out.writeArray(this::writePrivilegeInfo, privileges);
    }

    private PrivilegeInfo readPrivilegeInfo(StreamInput in) throws IOException {
        var name = in.readString();
        var implies = in.readStringArray();
        return new PrivilegeInfo(name, implies);
    }

    private void writePrivilegeInfo(StreamOutput out, PrivilegeInfo privilege) throws IOException {
        out.writeString(privilege.name());
        out.writeStringArray(privilege.implies());
    }

    private String[] toStringArray(PrivilegeInfo[] privileges) {
        final String[] names = new String[privileges.length];
        for (int i = 0; i < names.length; i++) {
            names[i] = privileges[i].name;
        }
        return names;
    }
}
