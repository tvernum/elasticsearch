/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.elasticsearch.common.ParsingException;
import org.elasticsearch.common.xcontent.XContentParserUtils;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentParserConfiguration;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.authz.privilege.IndexPrivilege;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class IndexAccessRestrictionsParser {

    static IndexAccessRestrictions parse(XContentParser parser) throws IOException {
        if (parser.currentToken() == null) {
            parser.nextToken();
        }
        if (parser.currentToken() == null) {
            // empty file
            return IndexAccessRestrictions.EMPTY;
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
        final List<IndexAccessRestrictions.Restriction> restrictions = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            restrictions.add(parseEntry(parser));
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.currentToken(), parser);

        return new IndexAccessRestrictions(restrictions);
    }

    static IndexAccessRestrictions parse(Path path) throws IOException {
        final XContentType xContentType = path.toString().endsWith(".json") ? XContentType.JSON : XContentType.YAML;
        try (
            InputStream in = Files.newInputStream(path, StandardOpenOption.READ);
            XContentParser parser = xContentType.xContent().createParser(XContentParserConfiguration.EMPTY, in)
        ) {
            return parse(parser);
        }
    }

    private static IndexAccessRestrictions.Restriction parseEntry(XContentParser parser) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
        String name = parser.currentName();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        IndexAccessRestrictions.SubjectList appliesTo = IndexAccessRestrictions.ALL_SUBJECTS;
        String[] indices = null;
        Set<String> privileges = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
            switch (parser.currentName()) {
                case "exclude":
                    appliesTo = IndexAccessRestrictions.negate(parseSubjectList(parser));
                    break;

                case "indices":
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, parser.nextToken(), parser);
                    indices = XContentParserUtils.parseList(parser, XContentParser::text).toArray(String[]::new);
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_ARRAY, parser.currentToken(), parser);
                    break;

                case "privileges":
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, parser.nextToken(), parser);
                    privileges = Set.copyOf(XContentParserUtils.parseList(parser, XContentParser::text));
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_ARRAY, parser.currentToken(), parser);
                    break;

                default:
                    XContentParserUtils.throwUnknownField(parser.currentName(), parser);
            }
        }

        if (indices == null) {
            throw new ParsingException(parser.getTokenLocation(), "Missing 'indices' field");
        }
        if (privileges == null) {
            throw new ParsingException(parser.getTokenLocation(), "Missing 'privileges' field");
        }

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.currentToken(), parser);
        return new IndexAccessRestrictions.Restriction(
            name,
            appliesTo,
            new IndexRestrictedRole.IndexAccessLimit(indices, IndexPrivilege.get(privileges))
        );
    }

    private static IndexAccessRestrictions.SubjectList parseSubjectList(XContentParser parser) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        XContentParserUtils.ensureFieldName(parser, parser.nextToken(), "roles");

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, parser.nextToken(), parser);
        final Set<String> roles = Set.copyOf(XContentParserUtils.parseList(parser, XContentParser::text));
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_ARRAY, parser.currentToken(), parser);

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser);

        return IndexAccessRestrictions.matchRoles(roles);
    }
}
