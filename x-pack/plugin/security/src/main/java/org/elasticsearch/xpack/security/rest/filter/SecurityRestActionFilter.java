/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.filter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.xpack.core.security.authc.Authentication;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Predicate;

public class SecurityRestActionFilter {

    public static final Setting<String> CONFIG_PATH_SETTING
        = Setting.simpleString("xpack.security.http.filter", Setting.Property.NodeScope);

    private static final Logger logger = LogManager.getLogger();

    private final boolean enabled;
    private final List<Rule> rules;

    public SecurityRestActionFilter(Environment environment) {
        final Settings settings = environment.settings();
        if (CONFIG_PATH_SETTING.exists(settings) == false) {
            logger.trace("Rest security filter [{}] is not enabled", CONFIG_PATH_SETTING.getKey());
            this.enabled = false;
            this.rules = List.of();
            return;
        }

        final Path path = environment.configFile().resolve(CONFIG_PATH_SETTING.get(settings));
        if (logger.isDebugEnabled()) {
            logger.debug("Rest security filter [{}] is [{}]", CONFIG_PATH_SETTING.getKey(), path.toAbsolutePath());
        }
        if (Files.exists(path) == false) {
            throw new ElasticsearchException("The file [{}] (for setting [{}]) does not exist",
                path.toAbsolutePath(), CONFIG_PATH_SETTING.getKey());
        }

        this.enabled = true;
        try {
            this.rules = List.copyOf(RestActionSecurityParser.parseRules(path));
        } catch (IOException e) {
            throw new ElasticsearchException("The file [{}] (for setting [{}]) cannot be read", e,
                path.toAbsolutePath(), CONFIG_PATH_SETTING.getKey());
        }
        logger.debug("Rest security filter [{}] is enabled with [{}] rule", CONFIG_PATH_SETTING.getKey(), rules.size());
    }

    public void authorize(Authentication authentication, RestRequest request) {
        if (permit(authentication, request) == false) {
            throw new ElasticsearchSecurityException("Rest action [{}] [{}] is not permitted for user [{}] from realm [{}]",
                RestStatus.FORBIDDEN,
                request.method(), request.path(),
                authentication.getUser().principal(), authentication.getSourceRealm().getName());
        }
    }

    public boolean permit(Authentication authentication, RestRequest request) {
        logger.trace("Check [{}][{}] for [{}]", request.method(), request.uri(), authentication);
        return enabled == false || this.rules.stream().anyMatch(r -> r.permit(authentication, request));
    }


    static class Rule {
        private final String name;
        private final List<Predicate<Authentication>> user;
        private final List<Predicate<RestRequest>> action;

        public Rule(String name, List<Predicate<Authentication>> user, List<Predicate<RestRequest>> action) {
            this.name = name;
            this.user = user;
            this.action = action;
        }

        public boolean permit(Authentication authentication, RestRequest request) {
            boolean permitRequest = this.action.stream().anyMatch(p -> p.test(request));
            logger.trace(() -> new ParameterizedMessage("request [{}] [{}] {} permitted by filter [{}]",
                request.method(), request.uri(), permitRequest ? "is" : "is not", name));
            if (permitRequest) {
                boolean permitUser = this.user.stream().anyMatch(p -> p.test(authentication));
                logger.trace(() -> new ParameterizedMessage("authentication [{}] {} permitted by filter [{}]",
                    authentication, permitUser ? "is" : "is not", name));
                if (permitUser) {
                    logger.debug("allowing request [{}][{}] for user [{}] in filter [{}]",
                        request.method(), request.path(), authentication.getUser().principal(), name);
                    return true;
                }
            }
            return false;
        }

        public String name() {
            return name;
        }
    }
}
