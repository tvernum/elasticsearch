/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.cluster.metadata;

import org.elasticsearch.cluster.DiffableUtils;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;

public record ProjectId(String uuid) {

    public static final DiffableUtils.KeySerializer<ProjectId> KEY_SERIALIZER = new DiffableUtils.KeySerializer<ProjectId>() {
        @Override
        public void writeKey(ProjectId key, StreamOutput out) throws IOException {
            out.writeString(key.uuid);
        }

        @Override
        public ProjectId readKey(StreamInput in) throws IOException {
            return new ProjectId(in.readString());
        }
    };

}
