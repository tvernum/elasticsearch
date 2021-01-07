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
public final class StoreSecretAction extends ActionType<StoreSecretResponse> {

    public static final String NAME = "cluster:admin/xpack/security/secrets/create";
    public static final StoreSecretAction INSTANCE = new StoreSecretAction();

    private StoreSecretAction() {
        super(NAME, StoreSecretResponse::new);
    }

}
