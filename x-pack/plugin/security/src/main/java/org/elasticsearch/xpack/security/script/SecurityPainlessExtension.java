/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.script;

import org.elasticsearch.painless.spi.PainlessExtension;
import org.elasticsearch.painless.spi.Whitelist;
import org.elasticsearch.painless.spi.WhitelistInstanceBinding;
import org.elasticsearch.painless.spi.WhitelistLoader;
import org.elasticsearch.script.ScriptContext;
import org.elasticsearch.script.ScriptModule;
import org.elasticsearch.xpack.security.Security;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static java.util.stream.Collectors.toMap;

public class SecurityPainlessExtension implements PainlessExtension {

    private static final Whitelist STATIC_WHITELIST = WhitelistLoader.loadFromResourceFiles(
        SecurityPainlessExtension.class,
        "security_whitelist.txt"
    );
    private final Security securityPlugin;

    // needed for Java modularization
    public SecurityPainlessExtension() {
        throw new UnsupportedOperationException();
    }

    // PluginsService.createExtension will call this method, and provide the plugin instance as a param
    public SecurityPainlessExtension(Security securityPlugin) {
        this.securityPlugin = securityPlugin;
    }

    @Override
    public Map<ScriptContext<?>, List<Whitelist>> getContextWhitelists() {
        final ActiveUserLoader loader = new ActiveUserLoader(securityPlugin::getSecurityContext);
        final Whitelist loaderWhitelist = new Whitelist(
            STATIC_WHITELIST.classLoader,
            List.of(),
            List.of(),
            List.of(),
            List.of(
                new WhitelistInstanceBinding(
                    getClass().getCanonicalName(),
                    loader,
                    "activeUser",
                    ActiveUser.class.getName(),
                    List.of(),
                    List.of()
                )
            )
        );
        final List<Whitelist> list = List.of(STATIC_WHITELIST, loaderWhitelist);
        return ScriptModule.RUNTIME_FIELDS_CONTEXTS.stream().collect(toMap(Function.identity(), ignore -> list));
    }

}
