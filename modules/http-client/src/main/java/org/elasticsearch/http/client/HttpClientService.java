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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

/**
 * Provides shared utility methods for working with {@link org.apache.http.nio.client.HttpAsyncClient}.
 */
public class HttpClientService implements HttpClientConfigurationCallback {
    private final List<HttpClientConfigurationCallback> callbacks;
    private final Logger logger;

    /**
     * Construct a new service using a list of configuration callback
     * @param callbacks The list of callbacks. This list is not copied, and any changes to the original list will be reflected in the
     *                  operation of the service.
     */
    HttpClientService(List<HttpClientConfigurationCallback> callbacks) {
        this.logger = LogManager.getLogger(getClass());
        this.callbacks = callbacks;
    }

    @Override
    public void configureHttpClient(String context, HttpHost host, HttpAsyncClientBuilder httpClientBuilder) {
        logger.trace("Calling [{}] callbacks for HTTP context [{}] to host [{}]", callbacks.size(), context, host);
        this.callbacks.forEach(c -> c.configureHttpClient(context, host, httpClientBuilder));
    }

}
