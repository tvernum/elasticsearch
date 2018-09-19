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

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

/**
 * Represents an "index" privilege in the {@link GetUserPrivilegesResponse}. This differs from the "index" object in a Role descriptor,
 * as it supports an array value for {@link #getFieldSecurity() field_security} and {@link #getQuery() query}.
 * See <a href="https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-get-user-privileges.html">the API docs</a>
 */
public class IndexMultiplePrivilege {

    private final List<String> names;
    private final List<String> privileges;
    private final List<FieldSecurity> fieldSecurity;
    private final List<String> query;

    public IndexMultiplePrivilege(List<String> names, List<String> privileges, List<FieldSecurity> fieldSecurity, List<String> query) {
        this.names = Collections.unmodifiableList(names);
        this.privileges = Collections.unmodifiableList(privileges);
        this.fieldSecurity = fieldSecurity == null ? Collections.emptyList() : Collections.unmodifiableList(fieldSecurity);
        this.query = query == null ? Collections.emptyList() : Collections.unmodifiableList(query);
    }

    public List<String> getNames() {
        return names;
    }

    public List<String> getPrivileges() {
        return privileges;
    }

    public List<FieldSecurity> getFieldSecurity() {
        return fieldSecurity;
    }

    public List<String> getQuery() {
        return query;
    }

    private static final ConstructingObjectParser<IndexMultiplePrivilege, Void> PARSER = new ConstructingObjectParser<>("index_privilege",
        true, IndexMultiplePrivilege::buildObjectFromParserArgs);

    @SuppressWarnings("unchecked")
    private static IndexMultiplePrivilege buildObjectFromParserArgs(Object[] args) {
        return new IndexMultiplePrivilege(
            (List<String>) args[0],
            (List<String>) args[1],
            (List<FieldSecurity>) args[2],
            (List<String>) args[3]
        );
    }

    static {
        PARSER.declareStringArray(constructorArg(), new ParseField("names"));
        PARSER.declareStringArray(constructorArg(), new ParseField("privileges"));
        PARSER.declareObjectArray(optionalConstructorArg(), (parser, ignore) -> FieldSecurity.fromXContent(parser),
            new ParseField("field_security"));
        PARSER.declareStringArray(optionalConstructorArg(), new ParseField("query"));
    }

    static IndexMultiplePrivilege fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    public static class FieldSecurity {
        private final List<String> grant;
        private final List<String> except;

        public FieldSecurity(List<String> grant, List<String> except) {
            this.grant = grant == null ? Collections.emptyList() : Collections.unmodifiableList(grant);
            this.except = except == null ? Collections.emptyList() : Collections.unmodifiableList(except);
        }

        public List<String> getGrant() {
            return grant;
        }

        public List<String> getExcept() {
            return except;
        }

        private static final ConstructingObjectParser<FieldSecurity, Void> PARSER = new ConstructingObjectParser<>("field_security", true,
            FieldSecurity::buildObjectFromParserArgs);

        @SuppressWarnings("unchecked")
        private static FieldSecurity buildObjectFromParserArgs(Object[] args) {
            return new FieldSecurity(
                (List<String>) args[0],
                (List<String>) args[1]
            );
        }

        static {
            PARSER.declareStringArray(optionalConstructorArg(), new ParseField("grant"));
            PARSER.declareStringArray(optionalConstructorArg(), new ParseField("except"));
        }

        private static FieldSecurity fromXContent(XContentParser parser) throws IOException {
            return PARSER.parse(parser, null);
        }
    }
}
