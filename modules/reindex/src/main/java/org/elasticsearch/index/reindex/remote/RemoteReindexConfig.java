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

package org.elasticsearch.index.reindex.remote;

import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.lucene.util.SPIClassIterator;
import org.elasticsearch.index.reindex.RemoteReindexConfiguration;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceConfigurationError;

public class RemoteReindexConfig implements RemoteReindexConfiguration<HttpAsyncClientBuilder> {

    private final List<RemoteReindexConfiguration<HttpAsyncClientBuilder>> configurations;

    public RemoteReindexConfig() {
        this.configurations = new ArrayList<>();
    }

    @Override
    public void configure(HttpAsyncClientBuilder clientBuilder) {
        this.configurations.forEach(c -> c.configure(clientBuilder));
    }

    /**
     * Loads the {@code ReindexClientConfiguration} implementations from the given class loader
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void loadSpi(ClassLoader loader) {
        SPIClassIterator<RemoteReindexConfiguration> iterator = SPIClassIterator.get(RemoteReindexConfiguration.class, loader);
        List<RemoteReindexConfiguration<HttpAsyncClientBuilder>> configurations = new ArrayList<>();
        while (iterator.hasNext()) {
            final Class<? extends RemoteReindexConfiguration> c = iterator.next();
            try {
                final RemoteReindexConfiguration rrc = c.getConstructor().newInstance();
                this.configurations.add((RemoteReindexConfiguration<HttpAsyncClientBuilder>) rrc);
            } catch (Exception e) {
                throw new ServiceConfigurationError("failed to load reindex configuration [" + c.getName() + "]", e);
            }
        }
    }

}
