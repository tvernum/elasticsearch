/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.http.client;

import org.apache.http.HttpHost;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.elasticsearch.common.Nullable;

/**
 * A functional interface for configuring a {@link HttpAsyncClientBuilder}.
 * This interface is loaded through SPI and the loaded configurations are exposed through {@link HttpClientService}.
 *
 */
@FunctionalInterface
public interface HttpClientConfigurationCallback {

    HttpClientConfigurationCallback NO_OP = (context, host, httpClientBuilder) -> {
        // no-op
    };

    /**
     * Configure a http client in a named context.
     * @param context The name of the context in which the client is to be used (typically a module or plugin name).
     * @param host The host to which the connection is being made, may be {@code null} if the host is not known, or there are multiple
     *             hosts.
     * @param httpClientBuilder The builder to be configured.
     */
    void configureHttpClient(String context, @Nullable HttpHost host, HttpAsyncClientBuilder httpClientBuilder);

}
