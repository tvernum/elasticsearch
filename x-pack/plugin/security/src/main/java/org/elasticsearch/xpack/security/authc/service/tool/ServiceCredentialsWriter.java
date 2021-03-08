/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.service.tool;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.core.security.authc.support.Hasher;
import org.elasticsearch.xpack.security.authc.service.ServiceAccountFileCredentialStore;
import org.elasticsearch.xpack.security.authc.service.ServiceAccountToken;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Supports writing the service credentials file, including updating existing files
 * @see ServiceAccountFileCredentialStore
 */
public class ServiceCredentialsWriter {

    private final Logger logger = LogManager.getLogger();

    private final Hasher hasher;
    private final Map<String, char[]> entries;

    public ServiceCredentialsWriter(Hasher hasher) {
        this.hasher = hasher;
        this.entries = new LinkedHashMap<>();
    }

    public void load(Path path) throws IOException {
        this.entries.putAll(ServiceAccountFileCredentialStore.load(path, logger, new TreeMap<>()));
    }

    public void write(Path path) throws IOException {
        List<String> lines = entries
            .entrySet()
            .stream()
            .map(e -> e.getKey() + ":" + new String(e.getValue()))
            .collect(Collectors.toUnmodifiableList());;
        Files.write(path, lines, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }

    public void add(ServiceAccountToken token) throws IOException {
        this.add(token.getQualifiedName(), token.getSecret());
    }

    private void add(String name, SecureString secret) {
        this.entries.put(name, hasher.hash(secret));
    }

}
