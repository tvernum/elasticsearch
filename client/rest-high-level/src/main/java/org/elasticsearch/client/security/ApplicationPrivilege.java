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

/**
 * Represents a "application" privilege in the {@link GetUserPrivilegesResponse}.
 * See <a href="https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-get-user-privileges.html">the API docs</a>
 */
public class ApplicationPrivilege {

    private final String application;
    private final List<String> privileges;
    private final List<String> resources;

    public ApplicationPrivilege(String application, List<String> privileges, List<String> resources) {
        this.application = application;
        this.privileges = Collections.unmodifiableList(privileges);
        this.resources = Collections.unmodifiableList(resources);
    }

    public String getApplication() {
        return application;
    }

    public List<String> getPrivileges() {
        return privileges;
    }

    public List<String> getResources() {
        return resources;
    }


    private static final ConstructingObjectParser<ApplicationPrivilege, Void> PARSER = new ConstructingObjectParser<>(
        "application_privilege", true, ApplicationPrivilege::buildObjectFromParserArgs);

    @SuppressWarnings("unchecked")
    private static ApplicationPrivilege buildObjectFromParserArgs(Object[] args) {
        return new ApplicationPrivilege(
            (String) args[0],
            (List<String>) args[1],
            (List<String>) args[2]);
    }

    static {
        PARSER.declareString(constructorArg(), new ParseField("application"));
        PARSER.declareStringArray(constructorArg(), new ParseField("privileges"));
        PARSER.declareStringArray(constructorArg(), new ParseField("resources"));
    }

    static ApplicationPrivilege fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }
}
