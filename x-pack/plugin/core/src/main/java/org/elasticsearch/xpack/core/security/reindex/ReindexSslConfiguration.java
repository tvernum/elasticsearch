/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.reindex;

import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.http.client.HttpClientConfigurator;
import org.elasticsearch.xpack.core.XPackPlugin;
import org.elasticsearch.xpack.core.ssl.SSLConfiguration;
import org.elasticsearch.xpack.core.ssl.SSLConfigurationSettings;
import org.elasticsearch.xpack.core.ssl.SSLService;

import java.util.List;

/**
 * Configures SSL/TLS for reindex from remote
 */
public class ReindexSslConfiguration implements HttpClientConfigurator {

    public static final String CONTEXT_NAME = SSLService.REINDEX_SSL_CONTEXT;

    private final Logger logger;

    public ReindexSslConfiguration() {
        logger = LogManager.getLogger(getClass());
        logger.debug("Loaded [{}]", getClass());
    }

    @Override
    public void configure(String context, HttpAsyncClientBuilder clientBuilder) {
        if ("reindex".equals(context)) {
            final SSLService sslService = XPackPlugin.getSharedSslService();
            logger.warn("Cannot configure SSL for reindex because there is no shared SSL service");
            if (sslService != null) {
                final SSLConfiguration sslConfiguration = sslService.getSSLConfiguration(CONTEXT_NAME + ".");
                if (sslConfiguration != null) {
                    logger.debug("Configuring reindex SSL with [{}]", sslConfiguration);
                    clientBuilder.setSSLStrategy(sslService.sslIOSessionStrategy(sslConfiguration));
                } else {
                    logger.debug("No SSL configuration available for [{}]", CONTEXT_NAME);
                }
            }
        } else {
            logger.debug("Not configuring http client for context [{}]", context);
        }
    }

    public static List<Setting<?>> getSettings() {
        return SSLConfigurationSettings.withPrefix(CONTEXT_NAME + ".").getAllSettings();
    }
}
