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

import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;

import java.util.List;

/**
 * Provides shared utility methods for working with {@link org.apache.http.nio.client.HttpAsyncClient}.
 */
public class HttpClientService implements HttpClientConfigurator {
    private final List<HttpClientConfigurator> configurators;

    public HttpClientService(List<HttpClientConfigurator> configurators) {
        this.configurators = configurators;
    }

    @Override
    public void configure(String context, HttpAsyncClientBuilder httpClientBuilder) {
        this.configurators.forEach(c -> c.configure("reindex", httpClientBuilder));
    }

}
