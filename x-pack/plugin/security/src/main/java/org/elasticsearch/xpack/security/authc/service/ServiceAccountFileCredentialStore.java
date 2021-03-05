/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.env.Environment;
import org.elasticsearch.watcher.FileWatcher;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.core.XPackPlugin;
import org.elasticsearch.xpack.core.security.authc.support.Hasher;
import org.elasticsearch.xpack.security.authc.ApiKeyService;
import org.elasticsearch.xpack.security.support.FileLineParser;
import org.elasticsearch.xpack.security.support.FileReloadListener;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class ServiceAccountFileCredentialStore {

    private final Logger logger = LogManager.getLogger();
    private final Path file;
    private volatile Map<String, char[]> credentialHashes;

    public ServiceAccountFileCredentialStore(Environment env, ResourceWatcherService resourceWatcherService) {
        file = XPackPlugin.resolveConfigFile(env, "service_credentials");
        FileWatcher watcher = new FileWatcher(file.getParent());
        watcher.addListener(new FileReloadListener(file, this::reloadFile));
        try {
            resourceWatcherService.add(watcher, ResourceWatcherService.Frequency.HIGH);
        } catch (IOException e) {
            throw new ElasticsearchException("failed to start watching users file [{}]", e, file.toAbsolutePath());
        }
        try {
            credentialHashes = parseFile(file, logger);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load service account credentials file [" + file + "]", e);
        }
    }

    public boolean authenticate(ApiKeyService.ApiKeyCredentials apiKey) {
        return Optional.ofNullable(this.credentialHashes.get(apiKey.getId()))
            .map(hash -> Hasher.verifyHash(apiKey.getSecret(), hash))
            .orElse(false);
    }

    private void reloadFile() {
        try {
            credentialHashes = parseFile(file, logger);
        } catch (Exception e) {
            logger.warn(new ParameterizedMessage("Failed to reload service credentials [{}]", file.toAbsolutePath()), e);
        }
    }

    private Map<String, char[]> parseFile(Path path, Logger logger) throws IOException {
        logger.trace("reading service credentials file [{}]...", path.toAbsolutePath());
        if (Files.exists(path) == false) {
            logger.trace("file [{}] does not exist", path.toAbsolutePath());
            return Map.of();
        }

        final Map<String, char[]> credentials = new HashMap<>();
        FileLineParser.parse(path, (line, lineNumber) -> {
            line = line.trim();

            final int colon = line.indexOf(':');
            if (colon == -1) {
                logger.warn("invalid format at line #{} of credentials file [{}] - missing ':' character - ", lineNumber, path);
                throw new IllegalStateException("Missing ':' character at line #" + lineNumber);
            }

            final String key = line.substring(0, colon);
            char[] hash = new char[line.length() - (colon + 1)];
            line.getChars(colon + 1, line.length(), hash, 0);

            // TODO Don't allow plaintext credentials here - Check that Hasher.resolveFromHash(hash) != NOOP
            logger.trace("parsed credentials for key [{}]", key);
            credentials.put(key, hash);
        });

        logger.debug("parsed [{}] credentials from file [{}]", credentials.size(), path.toAbsolutePath());
        return Map.copyOf(credentials);
    }
}
