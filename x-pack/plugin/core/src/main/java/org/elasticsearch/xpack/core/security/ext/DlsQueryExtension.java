/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.ext;

import org.elasticsearch.action.support.GroupedActionListener;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.ResolvedIndices;
import org.elasticsearch.xpack.core.security.authz.permission.DocumentSecurityQuery;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.user.User;

import java.util.Map;

public interface DlsQueryExtension {
    String name();

    DocumentSecurityQuery build(User user, Map<String, Object> config);

    /**
     * This method provides an opportunity for extensions to preload any values that are needed in order to {@link #build} the DLS query.
     * This is necessary because build needs to be synchronous, but the extension may need to perform asynchronous actions in order to
     * build the query - such asynchronous calls may be made here instead.
     * <br>
     * However, extensions should be very conservative in the work they do here - this method is called for <em>every</em> index level
     * request for any role that uses Document Level Security. Extensions should aggressively cache values, and only calculate values that
     * are relevant for the target indices and cannot be calculated synchronously in {@link #build}.
     */
    default void precache(
        Authentication authentication,
        Role role,
        ResolvedIndices requestedIndices,
        GroupedActionListener<Void> listener
    ) {
        listener.onResponse(null);
    }
}
