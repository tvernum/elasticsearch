/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.permission;

import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.xpack.core.security.support.MustacheTemplateEvaluator;
import org.elasticsearch.xpack.core.security.user.User;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class TemplatedSecurityQuery implements DocumentSecurityQuery {

    private final ScriptService scriptService;
    private final Script script;
    private final User user;

    public TemplatedSecurityQuery(ScriptService scriptService, Script script, User user) throws IOException {
        this.scriptService = scriptService;
        this.script = script;
        this.user = user;
    }

    @Override
    public String getQueryDsl() {
        final Map<String, Object> userModel = new HashMap<>();
        userModel.put("username", user.principal());
        userModel.put("full_name", user.fullName());
        userModel.put("email", user.email());
        userModel.put("roles", Arrays.asList(user.roles()));
        userModel.put("metadata", Collections.unmodifiableMap(user.metadata()));
        final Map<String, Object> extraParams = Collections.singletonMap("_user", userModel);
        return MustacheTemplateEvaluator.evaluate(scriptService, this.script, extraParams);
    }

    public Script getScript() {
        return script;
    }

    @Override
    public int compareTo(DocumentSecurityQuery other) {
        if (other instanceof TemplatedSecurityQuery tsq) {
            return compare(this.script, tsq.script);
        } else {
            return getClass().getName().compareTo(other.getClass().getName());
        }
    }

    private int compare(Script lhs, Script rhs) {
        final int cmp = lhs.getType().compareTo(rhs.getType());
        if (cmp != 0) {
            return cmp;
        }
        return lhs.getIdOrCode().compareTo(rhs.getIdOrCode());
    }
}
