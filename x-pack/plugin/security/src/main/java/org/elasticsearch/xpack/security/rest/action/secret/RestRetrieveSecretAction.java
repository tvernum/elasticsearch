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
import org.elasticsearch.xpack.core.security.action.secret.RetrieveSecretAction;
import org.elasticsearch.xpack.core.security.action.secret.RetrieveSecretRequest;
import org.elasticsearch.xpack.security.rest.action.SecurityBaseRestHandler;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.GET;

/**
 * Rest action to create an API key
 */
public final class RestRetrieveSecretAction extends SecurityBaseRestHandler {

    static final ConstructingObjectParser<RetrieveSecretRequest, RestRequest> PARSER = new ConstructingObjectParser<>(
        "retrieve_secret_request",
        false,
        (Object[] args, RestRequest request) -> new RetrieveSecretRequest(
            request.param("namespace"),
            request.param("id"),
            new SecureString(((String) args[0]).toCharArray())
        )
    );

    static {
        PARSER.declareString(ConstructingObjectParser.constructorArg(), new ParseField("password"));
    }

    /**
     * @param settings     the node's settings
     * @param licenseState the license state that will be used to determine if
     *                     security is licensed
     */
    public RestRetrieveSecretAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, "/_security/secret/{namespace}/{id}")
        );
    }

    @Override
    public String getName() {
        return "xpack_security_retrieve_secret";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        try (XContentParser parser = request.contentParser()) {
            final RetrieveSecretRequest retrieveSecretRequest = PARSER.parse(parser, request);
            return channel -> client.execute(RetrieveSecretAction.INSTANCE, retrieveSecretRequest, new RestToXContentListener<>(channel));
        }
    }
}
