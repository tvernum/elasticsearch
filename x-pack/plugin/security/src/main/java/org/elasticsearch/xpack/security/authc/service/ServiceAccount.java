/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.service;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.user.User;

import java.io.IOException;
import java.util.Objects;

public interface ServiceAccount {

    final class ServiceAccountId {
        private final String namespace;
        private final String service;


        public static ServiceAccountId parseAccountName(String userPrincipal) {
            final int split = userPrincipal.indexOf('/');
            if (split == -1) {
                throw new IllegalArgumentException(
                    "a service account name must be in the form {namespace}/{service}, but was [" + userPrincipal + "]");
            }
            return new ServiceAccountId(userPrincipal.substring(0, split), userPrincipal.substring(split + 1));
        }

        public ServiceAccountId(String namespace, String service) {
            this.namespace = Objects.requireNonNull(namespace, "Service Account namespace may not be null");
            this.service = Objects.requireNonNull(service, "A Service Account's service-name may not be null");
        }

        public ServiceAccountId(StreamInput in) throws IOException {
            this.namespace = in.readString();
            this.service = in.readString();
        }

        public void write(StreamOutput out) throws IOException {
            out.writeString(namespace);
            out.writeString(service);
        }

        public String namespace() {
            return namespace;
        }

        public String serviceName() {
            return service;
        }

        public String accountName() {
            return namespace + "/" + service;
        }

        @Override
        public String toString() {
            return accountName();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ServiceAccountId that = (ServiceAccountId) o;
            return namespace.equals(that.namespace) && service.equals(that.service);
        }

        @Override
        public int hashCode() {
            return Objects.hash(namespace, service);
        }
    }

    ServiceAccountId id();

    RoleDescriptor role();

    User asUser();
}
