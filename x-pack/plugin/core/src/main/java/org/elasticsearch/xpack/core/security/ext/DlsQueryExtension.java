/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.ext;

import org.elasticsearch.xpack.core.security.authz.permission.DocumentSecurityQuery;
import org.elasticsearch.xpack.core.security.user.User;

import java.util.Map;

public interface DlsQueryExtension {
    String name();

    DocumentSecurityQuery build(User user, Map<String, Object> config);
}
