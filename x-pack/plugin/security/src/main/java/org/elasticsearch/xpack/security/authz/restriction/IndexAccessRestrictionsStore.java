/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.ParsingException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.env.Environment;
import org.elasticsearch.watcher.FileChangesListener;
import org.elasticsearch.watcher.FileWatcher;
import org.elasticsearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Supplier;

public class IndexAccessRestrictionsStore implements Supplier<IndexAccessRestrictions> {

    private static final Logger logger = LogManager.getLogger(IndexAccessRestrictionsStore.class);

    static final Setting<Boolean> ENABLED_SETTING = Setting.boolSetting(
        "xpack.security.index_restrictions.enabled",
        false,
        Setting.Property.NodeScope
    );
    static final Setting<String> FILE_SETTING = Setting.simpleString(
        "xpack.security.index_restrictions.file",
        "index-restrictions.yml",
        Setting.Property.NodeScope
    );
    private final Boolean enabled;

    private volatile IndexAccessRestrictions limits;

    public IndexAccessRestrictionsStore(Environment environment, ResourceWatcherService resourceWatcherService) throws IOException {
        this.limits = IndexAccessRestrictions.EMPTY;
        this.enabled = ENABLED_SETTING.get(environment.settings());
        if (enabled == false) {
            return;
        }

        final Path limitsFile = environment.configDir().resolve(FILE_SETTING.get(environment.settings()));
        final FileWatcher watcher = new FileWatcher(limitsFile, true);
        watcher.addListener(new FileChangesListener() {
            @Override
            public void onFileCreated(Path file) {
                loadFile(file, false);
            }

            @Override
            public void onFileDeleted(Path file) {
                loadFile(file, false);
            }

            @Override
            public void onFileChanged(Path file) {
                loadFile(file, false);
            }
        });
        resourceWatcherService.add(watcher);
        loadFile(limitsFile, true);
    }

    @Override
    public IndexAccessRestrictions get() {
        return this.limits;
    }

    public static List<Setting<?>> getSettings() {
        return List.of(ENABLED_SETTING, FILE_SETTING);
    }

    private void loadFile(Path path, boolean strict) {
        if (Files.exists(path)) {
            try {
                this.limits = IndexAccessRestrictionsParser.parse(path);
                logger.info("Loaded [{}] index restrictions from file [{}]", limits.size(), path);
            } catch (IOException | ParsingException e) {
                logger.warn(Strings.format("Failed to read index restrictions from file [%s]", path.toAbsolutePath()), e);
                if (strict) {
                    throw new ElasticsearchSecurityException("Index restrictions file [" + path + "] is not valid", e);
                }
            }
        } else {
            this.limits = IndexAccessRestrictions.EMPTY;
        }
    }

}
