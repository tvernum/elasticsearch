/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.script;

import org.elasticsearch.xpack.core.security.SecurityContext;

import java.util.function.Supplier;

public class ActiveUserLoader {

    private final Supplier<SecurityContext> securityContext;

    public ActiveUserLoader(Supplier<SecurityContext> securityContext) {
        this.securityContext = securityContext;
    }

    public ActiveUser activeUser() {
        return new ActiveUser(securityContext.get().getAuthentication());
    }
}
