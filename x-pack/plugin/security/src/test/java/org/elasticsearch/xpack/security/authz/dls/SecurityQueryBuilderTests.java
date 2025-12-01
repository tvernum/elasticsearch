/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.dls;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.TermQueryBuilder;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.script.ScriptType;
import org.elasticsearch.script.TemplateScript;
import org.elasticsearch.script.mustache.MustacheScriptEngine;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xcontent.ToXContent;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xpack.core.security.authz.permission.DocumentSecurityQuery;
import org.elasticsearch.xpack.core.security.authz.permission.StaticSecurityQuery;
import org.elasticsearch.xpack.core.security.authz.permission.TemplatedSecurityQuery;
import org.elasticsearch.xpack.core.security.ext.DlsQueryExtension;
import org.elasticsearch.xpack.core.security.user.User;
import org.junit.Before;
import org.mockito.ArgumentCaptor;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.elasticsearch.xcontent.XContentFactory.jsonBuilder;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class SecurityQueryBuilderTests extends ESTestCase {
    private ScriptService scriptService;

    @Before
    public void setup() throws Exception {
        scriptService = mock(ScriptService.class);
    }

    public void testTemplating() throws Exception {
        User user = new User("_username", new String[] { "role1", "role2" }, "_full_name", "_email", Map.of("key", "value"), true);

        TemplateScript.Factory compiledTemplate = templateParams -> new TemplateScript(templateParams) {
            @Override
            public String execute() {
                return "rendered_text";
            }
        };

        when(scriptService.compile(any(Script.class), eq(TemplateScript.CONTEXT))).thenReturn(compiledTemplate);

        XContentBuilder builder = jsonBuilder();
        String query = Strings.toString(new TermQueryBuilder("field", "{{_user.username}}").toXContent(builder, ToXContent.EMPTY_PARAMS));
        Script script = new Script(ScriptType.INLINE, "mustache", query, Collections.singletonMap("custom", "value"));
        builder = jsonBuilder().startObject().field("template");
        script.toXContent(builder, ToXContent.EMPTY_PARAMS);
        var querySource = Strings.toString(builder.endObject());

        final SecurityQueryBuilder evaluator = new SecurityQueryBuilder(scriptService, List.of());
        final DocumentSecurityQuery queryObject = evaluator.build(querySource, user);

        final TemplatedSecurityQuery template = asInstanceOf(TemplatedSecurityQuery.class, queryObject);
        final String dsl = template.getQueryDsl();
        assertThat(dsl, equalTo("rendered_text"));

        ArgumentCaptor<Script> argument = ArgumentCaptor.forClass(Script.class);
        verify(scriptService).compile(argument.capture(), eq(TemplateScript.CONTEXT));
        Script usedScript = argument.getValue();
        assertThat(usedScript.getIdOrCode(), equalTo(script.getIdOrCode()));
        assertThat(usedScript.getType(), equalTo(script.getType()));
        assertThat(usedScript.getLang(), equalTo("mustache"));
        assertThat(usedScript.getOptions(), equalTo(script.getOptions()));
        assertThat(usedScript.getParams().size(), equalTo(2));
        assertThat(usedScript.getParams().get("custom"), equalTo("value"));

        Map<String, Object> userModel = new HashMap<>();
        userModel.put("username", user.principal());
        userModel.put("full_name", user.fullName());
        userModel.put("email", user.email());
        userModel.put("roles", Arrays.asList(user.roles()));
        userModel.put("metadata", user.metadata());
        assertThat(usedScript.getParams().get("_user"), equalTo(userModel));
    }

    public void testDocLevelSecurityTemplateWithOpenIdConnectStyleMetadata() throws Exception {
        User user = new User(
            randomAlphaOfLength(8),
            generateRandomStringArray(5, 5, false),
            randomAlphaOfLength(9),
            "sample@example.com",
            Map.of("oidc(email)", "sample@example.com"),
            true
        );

        final MustacheScriptEngine mustache = new MustacheScriptEngine(Settings.EMPTY);

        when(scriptService.compile(any(Script.class), eq(TemplateScript.CONTEXT))).thenAnswer(inv -> {
            assertThat(inv.getArguments(), arrayWithSize(2));
            Script script = (Script) inv.getArguments()[0];
            TemplateScript.Factory factory = mustache.compile(
                script.getIdOrCode(),
                script.getIdOrCode(),
                TemplateScript.CONTEXT,
                script.getOptions()
            );
            return factory;
        });

        final var template = """
            {
              "template": {
                "source": {
                  "term": {
                    "field": "{{_user.metadata.oidc(email)}}"
                  }
                }
              }
            }""";

        final SecurityQueryBuilder evaluator = new SecurityQueryBuilder(scriptService, List.of());
        String evaluated = evaluator.build(template, user).getQueryDsl();
        assertThat(evaluated, equalTo("""
            {"term":{"field":"sample@example.com"}}"""));
    }

    public void testSkipTemplating() throws Exception {
        XContentBuilder builder = jsonBuilder();
        final var querySource = Strings.toString(new TermQueryBuilder("field", "value").toXContent(builder, ToXContent.EMPTY_PARAMS));
        final SecurityQueryBuilder evaluator = new SecurityQueryBuilder(scriptService, List.of());
        String result = evaluator.build(querySource, null).getQueryDsl();
        assertThat(result, sameInstance(querySource));
        verifyNoMoreInteractions(scriptService);
    }

    public void testExtensions() {
        DlsQueryExtension ext1 = new DlsQueryExtension() {
            @Override
            public String name() {
                return "ext-1";
            }

            @Override
            public DocumentSecurityQuery build(User user, Map<String, Object> config) {
                return new StaticSecurityQuery(String.valueOf(config.get("q")));
            }
        };
        DlsQueryExtension ext2 = new DlsQueryExtension() {
            @Override
            public String name() {
                return "ext-2";
            }

            @Override
            public DocumentSecurityQuery build(User user, Map<String, Object> config) {
                return new StaticSecurityQuery(Strings.format("""
                    { "term": { "document.owner": "%s" } }
                    """.trim(), user.principal()));
            }
        };

        final User user = new User(
            "bob",
            generateRandomStringArray(5, 5, false),
            randomAlphaOfLength(9),
            randomAlphaOfLength(4) + "@example.com",
            Map.of(),
            true
        );

        final SecurityQueryBuilder evaluator = new SecurityQueryBuilder(scriptService, List.of(ext1, ext2));
        assertThat(evaluator.build("""
            {
                "extension": {
                    "name": "ext-1",
                    "config": {
                        "q": "foo"
                    }
                }
            }
            """, user).getQueryDsl(), equalTo("foo"));
        assertThat(evaluator.build("""
            {
                "extension": {
                    "name": "ext-2"
                }
            }
            """, user).getQueryDsl(), equalTo("{ \"term\": { \"document.owner\": \"bob\" } }"));
    }

}
