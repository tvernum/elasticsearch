/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action.secret;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Response after the successfully storing secrets
 */
public final class StoreSecretResponse extends ActionResponse implements ToXContentObject {

    private final String namespace;
    private final String id;
    private final boolean created;

    public StoreSecretResponse(String namespace, String id, boolean created) {
        this.namespace = namespace;
        this.id = id;
        this.created = created;
    }

    public StoreSecretResponse(StreamInput in) throws IOException {
        super(in);
        this.namespace = in.readString();
        this.id = in.readString();
        this.created = in.readBoolean();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(namespace);
        out.writeString(id);
        out.writeBoolean(created);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder
            .startObject()
            .field("namespace", namespace)
            .field("id", id)
            .field("created", created)
            .endObject();
    }
}
