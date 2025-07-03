/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.support;

import org.elasticsearch.TransportVersion;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.core.CheckedConsumer;
import org.elasticsearch.core.CheckedFunction;

import java.io.IOException;
import java.util.Base64;
import java.util.Objects;

public class EncodeToString {

    public static String encode(Writeable writeable) throws IOException {
        return encode(TransportVersion.current(), writeable::writeTo);
    }

    public static String encode(TransportVersion transportVersion, CheckedConsumer<StreamOutput, IOException> body) throws IOException {
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            out.setTransportVersion(transportVersion);
            TransportVersion.writeVersion(transportVersion, out);
            body.accept(out);
            out.flush();
            return Base64.getEncoder().encodeToString(BytesReference.toBytes(out.bytes()));
        }
    }

    public static <T> T decode(String encoded, CheckedFunction<StreamInput, T, IOException> body) throws IOException {
        Objects.requireNonNull(encoded);
        final byte[] bytes = Base64.getDecoder().decode(encoded);
        final StreamInput in = StreamInput.wrap(bytes);
        final TransportVersion transportVersion = TransportVersion.readVersion(in);
        in.setTransportVersion(transportVersion);
        return body.apply(in);
    }

}
