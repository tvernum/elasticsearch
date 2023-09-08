/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.test.rest;

import org.elasticsearch.common.settings.SecureString;
import org.junit.ClassRule;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

import static org.elasticsearch.test.rest.ESRestTestCase.basicAuthHeaderValue;

public interface RestTestCluster {

    record HttpHeader(String name, String value) {}

    HttpHeader getAdminCredentials();

    String getHttpAddress();

    class ExternalCluster implements RestTestCluster {
        private final String cluster;

        public ExternalCluster(String cluster) {
            this.cluster = cluster;
        }

        @Override
        public HttpHeader getAdminCredentials() {
            return null;
        }

        @Override
        public String getHttpAddress() {
            return cluster;
        }
    }

    class InternalCluster implements RestTestCluster {

        private final String address;
        private final HttpHeader credentials;

        InternalCluster(String address, Map.Entry<String, String> credentials) {
            this.address = address;
            String basicAuth = basicAuthHeaderValue(credentials.getKey(), new SecureString(credentials.getValue().toCharArray()));
            this.credentials = new HttpHeader("Authorization", basicAuth);
        }

        @Override
        public HttpHeader getAdminCredentials() {
            return credentials;
        }

        @Override
        public String getHttpAddress() {
            return address;
        }

        @SuppressWarnings("unchecked")
        public static InternalCluster build(ESRestTestCase testCase) {
            // HACK!
            return Arrays.stream(testCase.getClass().getFields()).map(field -> {
                final ClassRule annotation = field.getAnnotation(ClassRule.class);
                if (annotation == null) {
                    return null;
                }
                try {
                    final Object value = field.get(testCase);
                    final String address = invokeMethod(value, "getHttpAddresses", String.class);
                    final Map.Entry<String, String> credentials = invokeMethod(value, "getClusterCredentials", Map.Entry.class);
                    return new InternalCluster(address, credentials);
                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new RuntimeException(e);
                }
            }).filter(Objects::nonNull).findAny().orElse(null);
        }

        private static <T> T invokeMethod(Object target, String methodName, Class<? extends T> type) throws InvocationTargetException,
            IllegalAccessException {
            Method method;
            try {
                method = target.getClass().getMethod(methodName);
            } catch (NoSuchMethodException e) {
                return null;
            }
            final Object value = method.invoke(target);
            if (type.isInstance(value)) {
                return (T) type.cast(value);
            } else {
                return null;
            }
        }
    }
}
