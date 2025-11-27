/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.dls;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.ParsingException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.xcontent.XContentParserUtils;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.xcontent.XContentFactory;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentParserConfiguration;
import org.elasticsearch.xpack.core.security.authz.support.DlsQueryEvaluator;
import org.elasticsearch.xpack.core.security.support.MustacheTemplateEvaluator;
import org.elasticsearch.xpack.core.security.user.User;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SecurityQueryEvaluator implements DlsQueryEvaluator {

    private static final class Fields {
        private static final String TEMPLATE = "template";
        private static final String EXTENSION = "extension";
        private static final String NAME = "name";
        private static final String CONFIG = "config";
    }

    private final ScriptService scriptService;
    private final Map<String, DlsQueryExtension> extensions;

    public SecurityQueryEvaluator(ScriptService scriptService, List<DlsQueryExtension> extensions) {
        this.scriptService = scriptService;
        Map<String, DlsQueryExtension> map = new HashMap<>();
        for (DlsQueryExtension extension : extensions) {
            final String name = extension.name();
            final DlsQueryExtension existing = map.put(name, extension);
            if (existing != null) {
                throw new IllegalStateException(
                    "DLS extensions " + describe(existing) + " and " + describe(extension) + " have the same name [" + name + "]"
                );
            }
        }
        this.extensions = map;
    }

    private String describe(DlsQueryExtension extension) {
        return "["
            + extension.toString()
            + "] (class: "
            + extension.getClass().getName()
            + " in module: "
            + extension.getClass().getModule().getName()
            + ")";
    }

    @Override
    public String evaluate(String querySource, User user) {
        // EMPTY is safe here because we never use namedObject
        try (XContentParser parser = XContentFactory.xContent(querySource).createParser(XContentParserConfiguration.EMPTY, querySource)) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser);
            return switch (parser.currentName()) {
                case Fields.TEMPLATE -> evaluateTemplate(user, parser);
                case Fields.EXTENSION -> evaluateExtension(user, parser);
                case null, default -> querySource;
            };
        } catch (IOException ioe) {
            throw new ElasticsearchParseException("failed to parse query", ioe);
        }
    }

    private String evaluateExtension(User user, XContentParser parser) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        String extensionName = null;
        Map<String, Object> config = Map.of();

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser);
            switch (parser.currentName()) {
                case Fields.NAME -> {
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.VALUE_STRING, parser.nextToken(), parser);
                    extensionName = parser.text();
                }
                case Fields.CONFIG -> {
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                    config = parser.map();
                }
                case null, default -> XContentParserUtils.throwUnknownField(parser.currentName(), parser);
            }
        }

        if (extensionName == null) {
            throw new ParsingException(
                parser.getTokenLocation(),
                Strings.format("missing field [%s] from DLS extension", Fields.EXTENSION)
            );
        }

        final DlsQueryExtension extension = this.extensions.get(extensionName);
        if (extension == null) {
            throw new ElasticsearchSecurityException("no such DLS extension [" + extensionName + "]");
        }

        return extension.evaluate(user, config);
    }

    /** For cases where the query source is a template, this method parses the script, compiles the
     * script with user details parameters and then executes it to return the query string.
     * <p>
     * Note: This method always enforces "mustache" script language for the
     * template.
     *
     * @return resultant query string after compiling and executing the script.
     */
    private String evaluateTemplate(User user, XContentParser parser) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        Map<String, Object> userModel = new HashMap<>();
        userModel.put("username", user.principal());
        userModel.put("full_name", user.fullName());
        userModel.put("email", user.email());
        userModel.put("roles", Arrays.asList(user.roles()));
        userModel.put("metadata", Collections.unmodifiableMap(user.metadata()));
        Map<String, Object> extraParams = Collections.singletonMap("_user", userModel);
        return MustacheTemplateEvaluator.evaluate(scriptService, parser, extraParams);
    }
}
