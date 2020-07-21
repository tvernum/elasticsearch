/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.filter;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentParserUtils;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.support.Automatons;
import org.elasticsearch.xpack.security.rest.filter.SecurityRestActionFilter.Rule;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

final class RestActionSecurityParser {

    private static final ConstructingObjectParser<Rule, String> RULE_PARSER = new ConstructingObjectParser<>("rest_action_filter", false,
        (Object[] arr, String name) -> new Rule(name, (List<Predicate<Authentication>>) arr[0], (List<Predicate<RestRequest>>) arr[1])
    );
    private static final ConstructingObjectParser<Predicate<Authentication>, Void> USER_PARSER = new ConstructingObjectParser<>(
        "rest_action_filter.users", false, (Object[] arr) -> user((String) arr[0], (String) arr[1])
    );
    private static final ConstructingObjectParser<Predicate<RestRequest>, Void> ACTIONS_PARSER = new ConstructingObjectParser<>(
        "rest_action_filter.actions", false,
        (Object[] arr) -> {
            Predicate<RestRequest> grant = (Predicate<RestRequest>) arr[0];
            Predicate<RestRequest> except = (Predicate<RestRequest>) arr[1];
            if (except == null) {
                return grant;
            } else {
                return grant.and(except.negate());
            }
        }
    );
    private static final ConstructingObjectParser<Predicate<RestRequest>, Void> ACTION_PARSER = new ConstructingObjectParser<>(
        "rest_action_filter.actions.action", false, (Object[] arr) -> action((List<String>) arr[0], (List<String>) arr[1])
    );

    private static class Field {
        final static ParseField USERS = new ParseField("users");
        final static ParseField USERNAME = new ParseField("username");
        final static ParseField REALM = new ParseField("realm");
        final static ParseField ACTIONS = new ParseField("actions");
        final static ParseField GRANT = new ParseField("grant");
        final static ParseField EXCEPT = new ParseField("except");
        final static ParseField PATHS = new ParseField("paths");
        final static ParseField METHODS = new ParseField("methods");
    }

    static {
        RULE_PARSER.declareObjectArray(constructorArg(), (parser, ignore) -> USER_PARSER.parse(parser, null), Field.USERS);
        RULE_PARSER.declareObjectArray(constructorArg(), (parser, ignore) -> ACTIONS_PARSER.parse(parser, null), Field.ACTIONS);

        USER_PARSER.declareString(constructorArg(), Field.USERNAME);
        USER_PARSER.declareString(constructorArg(), Field.REALM);

        ACTIONS_PARSER.declareObject(constructorArg(), (parser, ignore) -> ACTION_PARSER.parse(parser, null), Field.GRANT);
        ACTIONS_PARSER.declareObject(optionalConstructorArg(), (parser, ignore) -> ACTION_PARSER.parse(parser, null), Field.EXCEPT);

        ACTION_PARSER.declareStringArray(constructorArg(), Field.PATHS);
        ACTION_PARSER.declareStringArray(constructorArg(), Field.METHODS);
    }

    static List<Rule> parseRules(Path path) throws IOException {
        try (InputStream in = Files.newInputStream(path, StandardOpenOption.READ)) {
            return parseRules(in);
        }
    }

    static List<Rule> parseRules(InputStream in) throws IOException {
        final List<Rule> rules = new ArrayList<>();
        try (XContentParser parser = yamlParser(in)) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser::getTokenLocation);
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser::getTokenLocation);
                final String filterName = parser.currentName();
                Rule rule = RULE_PARSER.parse(parser, filterName);
                rules.add(rule);
            }
        }
        return rules;
    }

    private static XContentParser yamlParser(InputStream in) throws IOException {
        return XContentType.YAML.xContent().createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, in);
    }


    private static Predicate<Authentication> user(String username, String realm) {
        final Predicate<String> usernamePredicate = Automatons.predicate(username);
        final Predicate<String> realmPredicate = Automatons.predicate(realm);

        return authentication -> usernamePredicate.test(authentication.getUser().principal())
            && realmPredicate.test(authentication.getSourceRealm().getName());
    }

    private static Predicate<RestRequest> action(List<String> paths, List<String> methods) {
        // TODO: Automatons interprets leading '/' as a regex ... need a workaround for paths
        // final Predicate<String> pathPredicate = Automatons.predicate(paths);
        final Predicate<String> pathPredicate = s -> paths.stream().anyMatch(p -> p.equals("*") || p.equals(s));
        final Predicate<String> methodPredicate = Automatons.predicate(methods);
        return req -> pathPredicate.test(req.path()) && methodPredicate.test(req.method().name());
    }

}
