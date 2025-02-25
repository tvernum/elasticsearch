/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.XContentTestUtils;
import org.elasticsearch.xcontent.XContentFactory;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentParserConfiguration;
import org.elasticsearch.xcontent.XContentType;
import org.hamcrest.Matchers;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class IndexAccessRestrictionsParserTests extends ESTestCase {

    public void testParseValidYaml() throws IOException {
        String yaml = """
            append_only_audit:
              exclude:
                roles:
                - superuser
              indices:
              - audit
              privileges:
              - create_doc
              - read
              - manage
              - monitor
              - view_index_metadata
            readonly_index:
              exclude:
                roles:
                - superuser
              indices:
              - readonly
              privileges:
              - read
              - monitor
              - view_index_metadata
            """;

        try (XContentParser parser = XContentFactory.xContent(XContentType.YAML).createParser(XContentParserConfiguration.EMPTY, yaml)) {
            final IndexAccessRestrictions limits = IndexAccessRestrictionsParser.parse(parser);

            assertThat(limits.size(), Matchers.is(2));
            assertThat(limits.size(), Matchers.is(2));

            final Map<String, Object> expected = Map.ofEntries(
                Map.entry(
                    "append_only_audit",
                    Map.ofEntries(
                        Map.entry("exclude", Map.of("roles", List.of("superuser"))),
                        Map.entry("indices", List.of("audit")),
                        Map.entry("privileges", List.of("create_doc", "read", "manage", "monitor", "view_index_metadata"))
                    )
                ),
                Map.entry(
                    "readonly_index",
                    Map.ofEntries(
                        Map.entry("exclude", Map.of("roles", List.of("superuser"))),
                        Map.entry("indices", List.of("readonly")),
                        Map.entry("privileges", List.of("read", "monitor", "view_index_metadata"))
                    )
                )
            );
            XContentTestUtils.differenceBetweenMapsIgnoringArrayOrder(XContentTestUtils.convertToMap(limits), expected);
        }
    }

}
