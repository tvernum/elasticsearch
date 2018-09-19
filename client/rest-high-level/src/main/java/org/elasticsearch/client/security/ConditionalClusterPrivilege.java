/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.client.security;

import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import static org.elasticsearch.common.xcontent.XContentParserUtils.ensureExpectedToken;

/**
 * Represents an "global" privilege in the {@link GetUserPrivilegesResponse}. This object is modeled as a nested map.
 * See <a href="https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-get-user-privileges.html">the API docs</a>
 */
public class ConditionalClusterPrivilege {

    private final String category;
    private final Map<String, Object> conditions;

    public ConditionalClusterPrivilege(String category, Map<String, Object> conditions) {
        this.category = category;
        this.conditions = Collections.unmodifiableMap(conditions);
    }

    public String getCategory() {
        return category;
    }

    public Map<String, Object> getConditions() {
        return conditions;
    }

    static ConditionalClusterPrivilege fromXContent(XContentParser parser) throws IOException {
        if (parser.currentToken() == null) {
            parser.nextToken();
        }
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser::getTokenLocation);
        ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser::getTokenLocation);
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser::getTokenLocation);
        final ConditionalClusterPrivilege privilege = new ConditionalClusterPrivilege(parser.currentName(), parser.map());
        ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.currentToken(), parser::getTokenLocation);
        ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser::getTokenLocation);
        return privilege;
    }
}
