/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authc.support;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.support.DLSRoleQueryValidator;
import org.elasticsearch.xpack.security.authc.ApiKeyService;
import org.elasticsearch.xpack.security.authz.store.PermissionsStore;

import java.util.Arrays;
import java.util.HashSet;

public class ApiKeyGenerator {

    private final ApiKeyService apiKeyService;
    private final PermissionsStore<?> permissionsStore;
    private final NamedXContentRegistry xContentRegistry;

    public ApiKeyGenerator(ApiKeyService apiKeyService, PermissionsStore<?> permissionsStore, NamedXContentRegistry xContentRegistry) {
        this.apiKeyService = apiKeyService;
        this.permissionsStore = permissionsStore;
        this.xContentRegistry = xContentRegistry;
    }

    public void generateApiKey(Authentication authentication, CreateApiKeyRequest request, ActionListener<CreateApiKeyResponse> listener) {
        if (authentication == null) {
            listener.onFailure(new ElasticsearchSecurityException("no authentication available to generate API key"));
            return;
        }
        apiKeyService.ensureEnabled();
        permissionsStore.getRoleDescriptors(new HashSet<>(Arrays.asList(authentication.getUser().roles())),
            ActionListener.wrap(roleDescriptors -> {
                    for (RoleDescriptor rd : roleDescriptors) {
                        try {
                            DLSRoleQueryValidator.validateQueryField(rd.getIndicesPrivileges(), xContentRegistry);
                        } catch (ElasticsearchException | IllegalArgumentException e) {
                            listener.onFailure(e);
                            return;
                        }
                    }
                    apiKeyService.createApiKey(authentication, request, roleDescriptors, listener);
                },
                listener::onFailure));

    }

}
