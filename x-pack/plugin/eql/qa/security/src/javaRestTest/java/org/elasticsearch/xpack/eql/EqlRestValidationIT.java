/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.eql;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.test.cluster.ElasticsearchCluster;
import org.elasticsearch.test.eql.EqlRestValidationTestCase;
import org.junit.ClassRule;

import static org.elasticsearch.xpack.eql.SecurityUtils.secureClientSettings;

public class EqlRestValidationIT extends EqlRestValidationTestCase {
    @ClassRule
    public static final ElasticsearchCluster cluster = EqlSecurityTestCluster.getCluster();

    @Override
    protected String getTestRestCluster() {
        return cluster.getHttpAddresses();
    }

    @Override
    protected Settings restClientSettings() {
        return secureClientSettings();
    }

    @Override
    protected boolean isSecurityEnabled() {
        return true;
    }
}
