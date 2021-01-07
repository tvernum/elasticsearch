/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action.secret;

import org.elasticsearch.action.ActionType;

/**
 * ActionType for the creation of an API key
 */
public final class RetrieveSecretAction extends ActionType<RetrieveSecretResponse> {

    public static final String NAME = "cluster:admin/xpack/security/secrets/read";
    public static final RetrieveSecretAction INSTANCE = new RetrieveSecretAction();

    private RetrieveSecretAction() {
        super(NAME, RetrieveSecretResponse::new);
    }

}
