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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.apache.lucene.util.SPIClassIterator;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.plugins.ExtensiblePlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.watcher.ResourceWatcherService;

import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.ServiceConfigurationError;

public class HttpClientPlugin extends Plugin implements ExtensiblePlugin {

    private final Logger logger = LogManager.getLogger(getClass());
    private final List<HttpClientConfigurator> clientConfigurations = new ArrayList<>();

    /**
     * Loads the {@code ReindexClientConfiguration} implementations from the given class loader
     */
    @Override
    public void reloadSPI(ClassLoader loader) {
        logger.debug(() -> new ParameterizedMessage("Reload SPI [{}] [{}]", loader,
            loader instanceof URLClassLoader ? ((URLClassLoader) loader).getURLs() : loader.getClass()));
        SPIClassIterator<HttpClientConfigurator> iterator = SPIClassIterator.get(HttpClientConfigurator.class, loader);
        List<HttpClientConfigurator> extensions = new ArrayList<>();
        while (iterator.hasNext()) {
            final Class<? extends HttpClientConfigurator> c = iterator.next();
            try {
                final HttpClientConfigurator configurator = c.getConstructor().newInstance();
                logger.debug("Loaded [{}]", configurator);
                extensions.add(configurator);
            } catch (Exception e) {
                throw new ServiceConfigurationError("failed to load reindex configuration [" + c.getName() + "]", e);
            }
        }
        this.clientConfigurations.addAll(extensions);
    }

    @Override
    public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool, ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry, Environment environment, NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry) {
        return Collections.singleton(new HttpClientService(clientConfigurations));
    }
}
