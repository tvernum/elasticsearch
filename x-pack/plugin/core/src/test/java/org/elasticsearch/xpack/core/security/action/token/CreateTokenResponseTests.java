/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action.token;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.test.ESTestCase;
import org.hamcrest.Matchers;

public class CreateTokenResponseTests extends ESTestCase {

    public void testToFromJson() throws Exception {
        final CreateTokenResponse response1 = new CreateTokenResponse(
            randomAlphaOfLengthBetween(12, 18),
            TimeValue.parseTimeValue(randomTimeValue(), "random"),
            randomBoolean() ? null : randomAlphaOfLengthBetween(2, 6),
            randomBoolean() ? null : randomAlphaOfLengthBetween(16, 24)
        );
        String json1 = Strings.toString(response1);
        assertThat(json1, Matchers.containsString(response1.getTokenString()));

        final CreateTokenResponse response2 = CreateTokenResponse.fromXContent(createParser(XContentType.JSON.xContent(), json1));
        String json2 = Strings.toString(response2);

        assertEquals(json1, json2);
    }
}
