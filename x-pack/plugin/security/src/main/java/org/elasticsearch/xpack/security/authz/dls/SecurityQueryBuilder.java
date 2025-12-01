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
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.xcontent.XContentFactory;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentParserConfiguration;
import org.elasticsearch.xpack.core.security.authz.permission.DocumentSecurityQuery;
import org.elasticsearch.xpack.core.security.authz.permission.StaticSecurityQuery;
import org.elasticsearch.xpack.core.security.authz.permission.TemplatedSecurityQuery;
import org.elasticsearch.xpack.core.security.authz.support.DlsQueryBuilder;
import org.elasticsearch.xpack.core.security.ext.DlsQueryExtension;
import org.elasticsearch.xpack.core.security.user.User;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SecurityQueryBuilder implements DlsQueryBuilder {

    private static final class Fields {
        private static final String TEMPLATE = "template";
        private static final String EXTENSION = "extension";
        private static final String NAME = "name";
        private static final String CONFIG = "config";
    }

    private final ScriptService scriptService;
    private final Map<String, DlsQueryExtension> extensions;

    public SecurityQueryBuilder(ScriptService scriptService, List<DlsQueryExtension> extensions) {
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
    public DocumentSecurityQuery build(String querySource, User user) {
        // EMPTY is safe here because we never use namedObject
        try (XContentParser parser = XContentFactory.xContent(querySource).createParser(XContentParserConfiguration.EMPTY, querySource)) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser);
            return switch (parser.currentName()) {
                case Fields.TEMPLATE -> buildTemplate(user, parser);
                case Fields.EXTENSION -> buildExtension(user, parser);
                case null, default -> new StaticSecurityQuery(querySource);
            };
        } catch (IOException ioe) {
            throw new ElasticsearchParseException("failed to parse query", ioe);
        }
    }

    private TemplatedSecurityQuery buildTemplate(User user, XContentParser parser) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        Script script = Script.parse(parser);
        return new TemplatedSecurityQuery(scriptService, script, user);
    }

    private DocumentSecurityQuery buildExtension(User user, XContentParser parser) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        String extensionName = null;
        Map<String, Object> config = Map.of();

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
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

        return extension.build(user, config);
    }

}
