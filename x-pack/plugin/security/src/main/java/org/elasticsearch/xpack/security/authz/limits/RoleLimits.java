/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.limits;

import org.elasticsearch.xpack.core.security.authz.permission.Role;

public interface RoleLimits {
    Role.Builder apply(Role.Builder builder);
}
