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

    public static boolean isServiceAccount(Authentication authentication) {
        return REALM_TYPE.equals(authentication.getAuthenticatedBy().getType());
    }

    public void authenticateWithToken(ServiceAccountToken token, ThreadContext threadContext, String nodeName,
                                      ActionListener<AuthenticationResult<Authentication>> listener) {

        if ("elastic".equals(token.getAccount().namespace()) == false) {
            listener.onResponse(AuthenticationResult.unsuccessful(
                "only 'elastic' service accounts are supported, but received [" + token.getAccount().accountName() + "]",
                null
            ));
            return;
        }

        final ServiceAccount account = getServiceAccount(token.getAccount());
        if (account == null) {
            listener.onResponse(AuthenticationResult.unsuccessful(
                "the [" + token.getAccount().accountName() + "] service account does not exist",
                null
            ));
            return;
        }

        if (fileCredentialStore.authenticate(token)) {
            listener.onResponse(success(account, token, nodeName));
        } else {
            listener.onResponse(AuthenticationResult.terminate(
                "failed to authenticate service account [" + token.getAccount().accountName() + "] with key [" + token.getTokenName() + "]",
                null
            ));
        }

    }

    private ServiceAccount getServiceAccount(ServiceAccountId accountId) {
        final ServiceAccount account = ACCOUNTS.get(accountId.serviceName());
        return account;
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

    private AuthenticationResult<Authentication> success(ServiceAccount account, ServiceAccountToken token, String nodeName) {
        final User user = account.asUser();
        final Authentication.RealmRef authenticatedBy = new Authentication.RealmRef(account.id().namespace(), REALM_TYPE, nodeName);
        return AuthenticationResult.success(
            new Authentication(user, authenticatedBy, null, Version.CURRENT, Authentication.AuthenticationType.TOKEN, Map.of(
                "token_name", token.getTokenName()
            )));
    }

}
