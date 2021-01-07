/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.action.secret;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;
import org.elasticsearch.xpack.core.security.action.secret.StoreSecretAction;
import org.elasticsearch.xpack.core.security.action.secret.StoreSecretRequest;
import org.elasticsearch.xpack.security.rest.action.SecurityBaseRestHandler;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.elasticsearch.rest.RestRequest.Method.POST;
import static org.elasticsearch.rest.RestRequest.Method.PUT;

/**
 * Rest action to create an API key
 */
public final class RestStoreSecretAction extends SecurityBaseRestHandler {

    static final ConstructingObjectParser<StoreSecretRequest, RestRequest> PARSER = new ConstructingObjectParser<>(
        "store_secret_request",
        false,
        (Object[] args, RestRequest request) -> new StoreSecretRequest(
            request.param("namespace"),
            request.param("id"),
            new SecureString(((String) args[0]).toCharArray()),
            (Map<String, Object>) args[1]
        )
    );

    static {
        PARSER.declareString(ConstructingObjectParser.constructorArg(), new ParseField("password"));
        PARSER.declareObject(ConstructingObjectParser.constructorArg(), (parser, ignore) -> parser.map(), new ParseField("secrets"));
    }

    /**
     * @param settings     the node's settings
     * @param licenseState the license state that will be used to determine if
     *                     security is licensed
     */
    public RestStoreSecretAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(POST, "/_security/secret/{namespace}/{id}"),
            new Route(PUT, "/_security/secret/{namespace}/{id}"));
    }

    @Override
    public String getName() {
        return "xpack_security_store_secret";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        try (XContentParser parser = request.contentParser()) {
            final StoreSecretRequest storeSecretRequest = PARSER.parse(parser, request);
            return channel -> client.execute(StoreSecretAction.INSTANCE, storeSecretRequest, new RestToXContentListener<>(channel));
        }
    }
}
