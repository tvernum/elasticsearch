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
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.test.ESTestCase;

import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

public class ConditionalClusterPrivilegeTests extends ESTestCase {

    @SuppressWarnings("unchecked")
    public void testFromXContent() throws Exception {
        String json = "{ \"application\": { \"manage\": { \"applications\": [ \"app01\", \"app02\" ] } } }";
        final XContentParser parser = createParser(XContentType.JSON.xContent(), json);
        final ConditionalClusterPrivilege privilege = ConditionalClusterPrivilege.fromXContent(parser);
        assertThat(privilege.getCategory(), equalTo("application"));
        assertThat(privilege.getConditions().size(), equalTo(1));
        assertThat(privilege.getConditions().get("manage"), instanceOf(Map.class));
        final Map<Object, Object> manage = (Map<Object, Object>) privilege.getConditions().get("manage");
        assertThat(manage.get("applications"), instanceOf(List.class));
        assertThat((List<?>) manage.get("applications"), contains("app01", "app02"));
    }
}
