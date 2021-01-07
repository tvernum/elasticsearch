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
import java.util.Collections;
import java.util.Map;

/**
 * Response after the successfully storing secrets
 */
public final class RetrieveSecretResponse extends ActionResponse implements ToXContentObject {

    private final String namespace;
    private final String id;
    private final Map<String, Object> secrets;

    public RetrieveSecretResponse(String namespace, String id, Map<String, Object> secrets) {
        this.namespace = namespace;
        this.id = id;
        this.secrets = Collections.unmodifiableMap(secrets);
    }

    public RetrieveSecretResponse(StreamInput in) throws IOException {
        super(in);
        this.namespace = in.readString();
        this.id = in.readString();
        this.secrets = in.readMap();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(namespace);
        out.writeString(id);
        out.writeMap(secrets);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder
            .startObject()
            .field("namespace", namespace)
            .field("id", id)
            .field("secrets", secrets)
            .endObject();
    }
}
