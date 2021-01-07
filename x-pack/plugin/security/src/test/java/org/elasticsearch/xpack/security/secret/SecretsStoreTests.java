/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.secret;

import org.elasticsearch.test.ESTestCase;
import org.hamcrest.Matchers;

public class SecretsStoreTests extends ESTestCase {

    public void testDocumentIdIsWithElasticsearchLimits() {
        final SecretsStore.SecretId id = new SecretsStore.SecretId(
            randomAlphaOfLengthBetween(8, 64),
            randomAlphaOfLengthBetween(8, 64)
        );
        final String documentId = SecretsStore.documentId(id);
        assertThat(documentId.length(), Matchers.lessThanOrEqualTo(512));
    }

}
