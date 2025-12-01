/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.permission;

import java.util.Objects;

public class StaticSecurityQuery implements DocumentSecurityQuery {

    private final String query;

    public StaticSecurityQuery(String query) {
        this.query = query;
    }

    @Override
    public String getQueryDsl() {
        return query;
    }

    @Override
    public int compareTo(DocumentSecurityQuery other) {
        if (other instanceof StaticSecurityQuery ssq) {
            return query.compareTo(ssq.query);
        } else {
            return getClass().getName().compareTo(other.getClass().getName());
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + query + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof StaticSecurityQuery that) {
            return Objects.equals(this.query, that.query);
        }
        return false;

    }

    @Override
    public int hashCode() {
        return Objects.hashCode(query);
    }
}
