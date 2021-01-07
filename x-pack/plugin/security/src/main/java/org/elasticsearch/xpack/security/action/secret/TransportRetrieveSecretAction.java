/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.action.secret;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.action.secret.RetrieveSecretAction;
import org.elasticsearch.xpack.core.security.action.secret.RetrieveSecretRequest;
import org.elasticsearch.xpack.core.security.action.secret.RetrieveSecretResponse;
import org.elasticsearch.xpack.security.secret.SecretsStore;

/**
 * Implementation of the action needed to create an API key
 */
public final class TransportRetrieveSecretAction extends HandledTransportAction<RetrieveSecretRequest, RetrieveSecretResponse> {

    private final SecretsStore secretsStore;

    @Inject
    public TransportRetrieveSecretAction(TransportService transportService, ActionFilters actionFilters, SecretsStore secretsStore) {
        super(RetrieveSecretAction.NAME, transportService, actionFilters, RetrieveSecretRequest::new);
        this.secretsStore = secretsStore;
    }

    @Override
    protected void doExecute(Task task, RetrieveSecretRequest request, ActionListener<RetrieveSecretResponse> listener) {
        SecretsStore.SecretId id = new SecretsStore.SecretId(request.getNamespace(), request.getId());
        secretsStore.readSecrets(id, request.getPassword(), ActionListener.delegateFailure(listener, (ignore, secret) -> {
                listener.onResponse(new RetrieveSecretResponse(id.namespace, id.id, secret.getContent()));
            }
        ));
    }
}
