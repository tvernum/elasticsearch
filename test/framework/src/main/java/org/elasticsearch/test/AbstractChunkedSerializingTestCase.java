/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.test;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStream;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ChunkedToXContent;
import org.elasticsearch.xcontent.ToXContent;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.function.ToIntFunction;

import static org.elasticsearch.test.AbstractXContentTestCase.chunkedXContentTester;
import static org.elasticsearch.xcontent.ToXContent.EMPTY_PARAMS;
import static org.elasticsearch.xcontent.XContentFactory.jsonBuilder;

public abstract class AbstractChunkedSerializingTestCase<T extends ChunkedToXContent & Writeable> extends AbstractSerializationTestCase<T> {

    @Override
    protected AbstractXContentTestCase.XContentTester<T> createXContentTester() {
        return chunkedXContentTester(this::createParser, this::createXContextTestInstance, getToXContentParams(), this::doParseInstance);
    }

    @Override
    protected ToXContent asXContent(T instance) {
        return ChunkedToXContent.wrapAsToXContent(instance);
    }

    @Override
    protected T createXContextTestInstance(XContentType xContentType) {
        return createTestInstance();
    }

    /**
     * Parses to a new instance using the provided {@link XContentParser}
     */
    protected abstract T doParseInstance(XContentParser parser) throws IOException;

    public static <T extends ChunkedToXContent> void assertChunkCount(T instance, ToIntFunction<T> expectedChunkCount) {
        assertChunkCount(instance, EMPTY_PARAMS, expectedChunkCount);
    }

    public static <T extends ChunkedToXContent> void assertChunkCount(
        T instance,
        ToXContent.Params params,
        ToIntFunction<T> expectedChunkCount
    ) {
        int chunkCount = 0;
        try (var builder = jsonBuilder()) {
            try {
                if (instance.isFragment()) {
                    builder.startObject();
                }
                final var iterator = instance.toXContentChunked(params);
                while (iterator.hasNext()) {
                    iterator.next().toXContent(builder, params);
                    chunkCount += 1;
                }
                if (instance.isFragment()) {
                    builder.endObject();
                }
            } catch (IOException e) {
                fail(e, "At chunk [%d] in instance [%s] with partial output '%s'", chunkCount, instance, getString(builder));
            }
        } // closing the builder verifies that the XContent is well-formed
        catch (IOException e) {
            fail(e);
        }
        assertEquals(expectedChunkCount.applyAsInt(instance), chunkCount);
    }

    private static String getString(XContentBuilder builder) throws IOException {
        builder.flush();
        OutputStream stream = builder.getOutputStream();
        BytesReference result;
        if (stream instanceof ByteArrayOutputStream) {
            result = new BytesArray(((ByteArrayOutputStream) stream).toByteArray());
        } else {
            result = ((BytesStream) stream).bytes();
        }
        return result.utf8ToString();
    }
}
