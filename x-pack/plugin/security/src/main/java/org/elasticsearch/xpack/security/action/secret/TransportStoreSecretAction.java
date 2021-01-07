/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.action.secret;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.action.secret.StoreSecretAction;
import org.elasticsearch.xpack.core.security.action.secret.StoreSecretRequest;
import org.elasticsearch.xpack.core.security.action.secret.StoreSecretResponse;
import org.elasticsearch.xpack.security.secret.SecretsStore;

/**
 * Implementation of the action needed to create an API key
 */
public final class TransportStoreSecretAction extends HandledTransportAction<StoreSecretRequest, StoreSecretResponse> {

    private final SecretsStore secretsStore;

    @Inject
    public TransportStoreSecretAction(TransportService transportService, ActionFilters actionFilters, SecretsStore secretsStore) {
        super(StoreSecretAction.NAME, transportService, actionFilters, StoreSecretRequest::new);
        this.secretsStore = secretsStore;
    }

    @Override
    protected void doExecute(Task task, StoreSecretRequest request, ActionListener<StoreSecretResponse> listener) {
        SecretsStore.SecretId id = new SecretsStore.SecretId(request.getNamespace(), request.getId());
        secretsStore.writeSecrets(id, DocWriteRequest.OpType.CREATE, request.getContent(), request.getPassword(),
            ActionListener.delegateFailure(listener, (ignore, result) -> {
                    listener.onResponse(new StoreSecretResponse(id.namespace, id.id, result == DocWriteResponse.Result.CREATED));
                }
            ));
    }
}
