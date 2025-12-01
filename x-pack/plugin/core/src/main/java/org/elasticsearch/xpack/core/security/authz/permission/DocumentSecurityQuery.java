/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.permission;

/**
 * An abstraction over different types of Document Level Security queries (static queries, templates, extensions)
 * This exists so that we can parse the JSON form once and evaluate as much as necessary up front so that generating
 * the final query can be doe synchronously
 */
public interface DocumentSecurityQuery extends Comparable<DocumentSecurityQuery> {

    /**
     * Returns the underlying query as a string in Query DSL (JSON) format.
     * This may require some amount of runtime execution (such as evaluating a template)
     * <br>
     * If the source does not contain a dynamic query, then this method will return the query source without any modifications.
     */
    String getQueryDsl();
}
