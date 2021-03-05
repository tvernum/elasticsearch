/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor.IndicesPrivileges;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.security.authc.ApiKeyService;
import org.elasticsearch.xpack.security.authc.ApiKeyService.ApiKeyCredentials;
import org.elasticsearch.xpack.security.authc.service.ServiceAccount.ServiceAccountId;
import org.elasticsearch.xpack.security.support.TracingListener;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class ServiceAccountService {

    public static final String REALM_TYPE = "service_account";

    private final Logger logger = LogManager.getLogger();

    private static final ServiceAccount FLEET_ACCOUNT = new ElasticServiceAccount("fleet",
        new RoleDescriptor(
            "elastic/fleet",
            new String[]{"monitor", "manage_own_api_key"},
            new IndicesPrivileges[]{
                IndicesPrivileges
                    .builder()
                    .indices("logs-*", "metrics-*", "traces-*")
                    .privileges("write", "create_index", "auto_configure")
                    .build()
            },
            null,
            null,
            null,
            null,
            null
        ));

    private static final Map<String, ServiceAccount> ACCOUNTS = List.of(FLEET_ACCOUNT)
        .stream()
        .collect(Collectors.toMap(a -> a.id().serviceName(), Function.identity()));

    private static final String SERVICE_ACCOUNT_KEY = "_xpack_service_account";

    private final ServiceAccountFileCredentialStore fileCredentialStore;

    public ServiceAccountService(ServiceAccountFileCredentialStore fileCredentialStore) {
        this.fileCredentialStore = fileCredentialStore;
    }

    public boolean isServiceAccount(Authentication authentication) {
        return REALM_TYPE.equals(authentication.getAuthenticatedBy().getType());
    }

    public void authenticateWithApiKey(ApiKeyCredentials credentials, ThreadContext threadContext,
                                       ActionListener<AuthenticationResult> listener) {
        listener = new TracingListener<>(listener, "service account authentication", logger);
        final String keyId = credentials.getId();

        // Split of the key name
        final int split = keyId.lastIndexOf('/');
        if (split == -1) {
            listener.onResponse(AuthenticationResult.unsuccessful(
                "service account API Keys must contain two '/' characters, but received [" + keyId + "]",
                null
            ));
            return;
        }

        final ServiceAccountId accountId;
        try {
            accountId = ServiceAccountId.parseAccountName(keyId.substring(0, split));
        } catch (Exception e) {
            listener.onResponse(AuthenticationResult.unsuccessful("cannot parse service account name", e));
            return;
        }

        final String key = keyId.substring(split+1);

        if ("elastic".equals(accountId.namespace()) == false) {
            listener.onResponse(AuthenticationResult.unsuccessful(
                "only 'elastic' service accounts are supported, but received [" + keyId + "]",
                null
            ));
            return;
        }

        final ServiceAccount account = getServiceAccount(accountId);
        if (account == null) {
            listener.onResponse(AuthenticationResult.unsuccessful(
                "the [" + accountId.accountName() + "] service account does not exist",
                null
            ));
            return;
        }

        if (fileCredentialStore.authenticate(credentials)) {
            listener.onResponse(success(account, credentials));
        } else {
            listener.onResponse(AuthenticationResult.terminate(
                "failed to authenticate service account [" + accountId.accountName() + "] with key [" + key + "]",
                null
            ));
        }

    }

    private ServiceAccount getServiceAccount(ServiceAccountId accountId) {
        final ServiceAccount account = ACCOUNTS.get(accountId.serviceName());
        return account;
    }

    public Authentication buildAuthentication(AuthenticationResult authResult, String nodeName) {
        if (false == authResult.isAuthenticated()) {
            throw new IllegalArgumentException("Service Account authentication result must be successful");
        }
        final User user = authResult.getUser();
        // TODO, this is horrible
        final ElasticServiceAccount account = (ElasticServiceAccount) authResult.getMetadata().get(SERVICE_ACCOUNT_KEY);
        final String apiKey = (String) authResult.getMetadata().get(ApiKeyService.API_KEY_ID_KEY);
        final Authentication.RealmRef authenticatedBy = new Authentication.RealmRef(account.id().namespace(), REALM_TYPE, nodeName);
        return new Authentication(user, authenticatedBy, null, Version.CURRENT, Authentication.AuthenticationType.API_KEY,
            Map.ofEntries(
                Map.entry(ApiKeyService.API_KEY_ID_KEY, apiKey)
            ));
    }

    public void getRoleDescriptor(Authentication authentication, ActionListener<RoleDescriptor> listener) {
        listener = new TracingListener(listener, "build service account role", logger);
        assert isServiceAccount(authentication);

        final ServiceAccountId accountId = ServiceAccountId.parseAccountName(authentication.getUser().principal());
        final ServiceAccount account = getServiceAccount(accountId);
        if (account == null) {
            listener.onFailure(new ElasticsearchSecurityException(
                "cannot load role for service account [" + accountId.accountName() + "] - no such service account"
            ));
            return;
        }
        listener.onResponse(account.role());
    }

    private AuthenticationResult success(ServiceAccount account, ApiKeyCredentials apiKey) {
        final Map<String, Object> metadata = Map.ofEntries(
            Map.entry(ApiKeyService.API_KEY_ID_KEY, apiKey.getId()),
            Map.entry(SERVICE_ACCOUNT_KEY, account)
        );
        return AuthenticationResult.success(account.asUser(), metadata);
    }

}
