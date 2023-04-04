/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.script;

import org.elasticsearch.xpack.core.security.authc.Authentication;

public class ActiveUser {

    private final Authentication authentication;

    public ActiveUser(Authentication authentication) {
        this.authentication = authentication;
    }

    public String username() {
        return authentication.getEffectiveSubject().getUser().principal();
    }

}
