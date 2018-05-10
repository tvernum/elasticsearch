/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.client;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.action.token.CreateTokenRequest;

import java.io.IOException;

import static org.elasticsearch.client.RequestConverters.createContentType;

final class XPackRequestConverters {

    private XPackRequestConverters() {
    }

    static Request createToken(CreateTokenRequest createTokenRequest) throws IOException {
        final Request request = new Request(HttpPost.METHOD_NAME, "/_xpack/security/oauth2/token");
        request.setEntity(createEntity(createTokenRequest));
        return request;
    }

    private static HttpEntity createEntity(ToXContent toXContent) throws IOException {
        return createEntity(toXContent, XContentType.JSON);
    }

    private static HttpEntity createEntity(ToXContent toXContent, XContentType xContentType) throws IOException {
        BytesRef source = XContentHelper.toXContent(toXContent, xContentType, false).toBytesRef();
        return new ByteArrayEntity(source.bytes, source.offset, source.length, createContentType(xContentType));
    }

}
