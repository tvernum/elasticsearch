/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.client;

import org.apache.http.Header;
import org.elasticsearch.common.CheckedConsumer;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.security.action.token.CreateTokenRequest;
import org.elasticsearch.xpack.core.security.action.token.CreateTokenResponse;

import java.io.IOException;
import java.util.List;

import static java.util.Collections.emptySet;

public class XPackRestClient extends RestHighLevelClient {
    public XPackRestClient(RestClientBuilder restClientBuilder) {
        super(restClientBuilder);
    }

    protected XPackRestClient(RestClientBuilder restClientBuilder, List<NamedXContentRegistry.Entry> namedXContentEntries) {
        super(restClientBuilder, namedXContentEntries);
    }

    protected XPackRestClient(RestClient restClient, CheckedConsumer<RestClient, IOException> doClose, List<NamedXContentRegistry.Entry> namedXContentEntries) {
        super(restClient, doClose, namedXContentEntries);
    }

    /**
     * Executes a request using the Create Token API
     * <p>
     * See <a href="https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-tokens.html">Token Management APIs
     * on elastic.co</a>.
     */
    public final CreateTokenResponse createToken(CreateTokenRequest createTokenRequest, Header... headers) throws IOException {
        return performRequestAndParseEntity(createTokenRequest, XPackRequestConverters::createToken, CreateTokenResponse::fromXContent,
            emptySet(), headers);
    }


}
