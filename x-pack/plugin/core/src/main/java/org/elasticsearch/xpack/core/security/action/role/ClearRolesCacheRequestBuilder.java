/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action.role;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.action.support.nodes.NodesOperationRequestBuilder;
import org.elasticsearch.client.ElasticsearchClient;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ObjectParser;
import org.elasticsearch.common.xcontent.XContent;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Request builder for the {@link ClearRolesCacheRequest}
 */
public class ClearRolesCacheRequestBuilder extends NodesOperationRequestBuilder<ClearRolesCacheRequest, ClearRolesCacheResponse,
    ClearRolesCacheRequestBuilder> {

    private static final ObjectParser<ClearRolesCacheRequest, Void> PARSER = new ObjectParser<>("clear_roles_cache");

    static {
        PARSER.declareStringArray((req, val) -> {
            if (req.names() != null && req.names().length != 0) {
                throw new IllegalStateException("Cannot specify role names as both a parameter and in body content");
            }
            req.names(val.toArray(new String[val.size()]));
        }, Fields.NAME);
        PARSER.declareStringArray((req, val) -> req.applications(val.toArray(new String[val.size()])), Fields.APPLICATION);
    }

    public ClearRolesCacheRequestBuilder(ElasticsearchClient client) {
        this(client, ClearRolesCacheAction.INSTANCE, new ClearRolesCacheRequest());
    }

    public ClearRolesCacheRequestBuilder(ElasticsearchClient client, ClearRolesCacheAction action, ClearRolesCacheRequest request) {
        super(client, action, request);
    }

    /**
     * Set the roles to be cleared
     *
     * @param names the names of the roles that should be cleared
     * @return the builder instance
     */
    public ClearRolesCacheRequestBuilder names(String... names) {
        request.names(names);
        return this;
    }

    public ClearRolesCacheRequestBuilder source(BytesReference source, XContentType xContentType) throws IOException {
        Objects.requireNonNull(xContentType);
        final XContent xContent = xContentType.xContent();
        try (InputStream stream = source.streamInput();
             // EMPTY is ok here because we never call namedObject
             XContentParser parser = xContent.createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, stream)) {
            XContentParser.Token token = parser.currentToken();
            if (token == null) {
                token = parser.nextToken();
            }
            if (token == XContentParser.Token.START_OBJECT) {
                PARSER.parse(parser, request, null);
            } else {
                throw new ElasticsearchParseException("expected an object but found {} instead", token);
            }
        }
        return this;
    }

    private interface Fields {
        ParseField NAME = new ParseField("name");
        ParseField APPLICATION = new ParseField("application");
    }
}
