/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action.token;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ObjectParser;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.Objects;

/**
 * Response containing the token string that was generated from a token creation request. This
 * object also contains the scope and expiration date. If the scope was not provided or if the
 * provided scope matches the scope of the token, then the scope value is <code>null</code>
 */
public final class CreateTokenResponse extends ActionResponse implements ToXContentObject {

    private static final ConstructingObjectParser<CreateTokenResponse, Void> PARSER = new ConstructingObjectParser<>("token_response",
        a -> new CreateTokenResponse((String) a[0], (TimeValue) a[1], (String) a[2], (String) a[3]));

    static {
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), Fields.ACCESS_TOKEN);
        PARSER.declareField(ConstructingObjectParser.optionalConstructorArg(),
            parser -> TimeValue.timeValueSeconds(parser.longValue()), Fields.EXPIRES_IN, ObjectParser.ValueType.LONG);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), Fields.SCOPE);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), Fields.REFRESH_TOKEN);
        PARSER.declareString((r, s) -> { /* no-op */ }, Fields.TYPE);
    }

    private String tokenString;
    private TimeValue expiresIn;
    private String scope;
    private String refreshToken;

    CreateTokenResponse() {
    }

    public CreateTokenResponse(String tokenString, TimeValue expiresIn, String scope, String refreshToken) {
        this.tokenString = Objects.requireNonNull(tokenString);
        this.expiresIn = Objects.requireNonNull(expiresIn);
        this.scope = scope;
        this.refreshToken = refreshToken;
    }

    public String getTokenString() {
        return tokenString;
    }

    public String getScope() {
        return scope;
    }

    public TimeValue getExpiresIn() {
        return expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(tokenString);
        out.writeTimeValue(expiresIn);
        out.writeOptionalString(scope);
        if (out.getVersion().onOrAfter(Version.V_6_2_0)) {
            out.writeString(refreshToken);
        }
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        tokenString = in.readString();
        expiresIn = in.readTimeValue();
        scope = in.readOptionalString();
        if (in.getVersion().onOrAfter(Version.V_6_2_0)) {
            refreshToken = in.readString();
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .field(Fields.ACCESS_TOKEN.getPreferredName(), tokenString)
            .field(Fields.TYPE.getPreferredName(), "Bearer")
            .field(Fields.EXPIRES_IN.getPreferredName(), expiresIn.seconds());
        if (refreshToken != null) {
            builder.field(Fields.REFRESH_TOKEN.getPreferredName(), refreshToken);
        }
        // only show the scope if it is not null
        if (scope != null) {
            builder.field(Fields.SCOPE.getPreferredName(), scope);
        }
        return builder.endObject();
    }

    public static CreateTokenResponse fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    private static final class Fields {
        static final ParseField SCOPE = new ParseField("scope");
        static final ParseField REFRESH_TOKEN = new ParseField("refresh_token");
        static final ParseField EXPIRES_IN = new ParseField("expires_in");
        static final ParseField TYPE = new ParseField("type");
        static final ParseField ACCESS_TOKEN = new ParseField("access_token");
    }
}
