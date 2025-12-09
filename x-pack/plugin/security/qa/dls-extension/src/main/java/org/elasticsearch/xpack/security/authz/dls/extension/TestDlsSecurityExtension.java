/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.dls.extension;

import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.ext.DlsQueryExtension;

import java.util.List;

public class TestDlsSecurityExtension implements SecurityExtension {

    @Override
    public List<DlsQueryExtension> getDocumentLevelSecurityExtensions(SecurityComponents components) {
        return List.of(new TestDlsQueryExtension(components.client()));
    }
}
