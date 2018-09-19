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

import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;

/**
 * The response for the {@link org.elasticsearch.client.SecurityClient#getUserPrivileges(GetUserPrivilegesRequest, RequestOptions)} API.
 * See <a href="https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-get-user-privileges.html">the API docs</a>
 */
public class GetUserPrivilegesResponse {

    private List<String> cluster;
    private List<ConditionalClusterPrivilege> global;
    private List<IndexMultiplePrivilege> index;
    private List<ApplicationPrivilege> application;
    private List<String> runAs;

    public GetUserPrivilegesResponse(List<String> cluster, List<ConditionalClusterPrivilege> global, List<IndexMultiplePrivilege> index,
                                     List<ApplicationPrivilege> application, List<String> runAs) {
        this.cluster = Collections.unmodifiableList(cluster);
        this.global = Collections.unmodifiableList(global);
        this.index = Collections.unmodifiableList(index);
        this.application = Collections.unmodifiableList(application);
        this.runAs = Collections.unmodifiableList(runAs);
    }

    public List<String> getCluster() {
        return cluster;
    }

    public List<ConditionalClusterPrivilege> getGlobal() {
        return global;
    }

    public List<IndexMultiplePrivilege> getIndex() {
        return index;
    }

    public List<ApplicationPrivilege> getApplication() {
        return application;
    }

    public List<String> getRunAs() {
        return runAs;
    }

    private static final ConstructingObjectParser<GetUserPrivilegesResponse, Void> PARSER = new ConstructingObjectParser<>(
        "get_user_privileges_response", true, GetUserPrivilegesResponse::buildResponseFromParserArgs);

    @SuppressWarnings("unchecked")
    private static GetUserPrivilegesResponse buildResponseFromParserArgs(Object[] args) {
        return new GetUserPrivilegesResponse(
            (List<String>) args[0],
            (List<ConditionalClusterPrivilege>) args[1],
            (List<IndexMultiplePrivilege>) args[2],
            (List<ApplicationPrivilege>) args[3],
            (List<String>) args[4]
        );
    }

    static {
        PARSER.declareStringArray(constructorArg(), new ParseField("cluster"));
        PARSER.declareObjectArray(constructorArg(), (parser, ignore) -> ConditionalClusterPrivilege.fromXContent(parser),
            new ParseField("global"));
        PARSER.declareObjectArray(constructorArg(), (parser, ignore) -> IndexMultiplePrivilege.fromXContent(parser),
            new ParseField("indices"));
        PARSER.declareObjectArray(constructorArg(), (parser, ignore) -> ApplicationPrivilege.fromXContent(parser),
            new ParseField("applications"));
        PARSER.declareStringArray(constructorArg(), new ParseField("run_as"));
    }

    public static GetUserPrivilegesResponse fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }
}
