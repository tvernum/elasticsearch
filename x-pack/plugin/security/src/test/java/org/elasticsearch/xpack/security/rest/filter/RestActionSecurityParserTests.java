/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.filter;

import org.elasticsearch.test.ESTestCase;
import org.hamcrest.Matchers;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class RestActionSecurityParserTests extends ESTestCase {

    public void testParseRoles() throws Exception {
        final String yml = "# Operator filter allows GET/PUT cluster settings for the \"operator_access\" user\n" +
            "operator:\n" +
            "  users:\n" +
            "  - username: \"operator_access\"\n" +
            "    realm: \"default_file\"\n" +
            "  actions:\n" +
            "  - grant:\n" +
            "      paths:\n" +
            "      - \"/_cluster/settings\"\n" +
            "      methods:\n" +
            "      - \"GET\"\n" +
            "      - \"PUT\"\n" +
            "\n" +
            "# Default filter rejects PUT cluster settings for all users\n" +
            "default:\n" +
            "  users:\n" +
            "  - username: \"*\"\n" +
            "    realm: \"*\"\n" +
            "  actions:\n" +
            "  - grant:\n" +
            "      paths:\n" +
            "      - \"*\"\n" +
            "      methods:\n" +
            "      - \"*\"\n" +
            "    except:\n" +
            "      paths:\n" +
            "      - \"/_cluster/settings\"\n" +
            "      methods:\n" +
            "      - PUT\n";
        try (ByteArrayInputStream in = new ByteArrayInputStream(yml.getBytes(StandardCharsets.UTF_8))) {
            List<SecurityRestActionFilter.Rule> rules = RestActionSecurityParser.parseRules(in);
            assertThat(rules, Matchers.hasSize(2));
            assertThat(rules.get(0).name(), Matchers.equalTo("operator"));
            assertThat(rules.get(1).name(), Matchers.equalTo("default"));
        }
    }

}
