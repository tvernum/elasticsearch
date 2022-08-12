/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.security.action.privilege;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.io.stream.StreamInput;

import java.io.IOException;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Request to retrieve built-in (cluster/index) privileges.
 */
public final class GetBuiltinPrivilegesRequest extends ActionRequest {

    public enum Format {
        FLAT,
        TREE;

        public static final String DEFAULT_FORMAT_NAME = FLAT.name();

        public static Format parse(String name) {
            for (var format : values()) {
                if (format.name().equalsIgnoreCase(name)) {
                    return format;
                }
            }
            throw new IllegalArgumentException(
                "Invalid format ["
                    + name
                    + "], valid options are ["
                    + Stream.of(values()).map(Format::name).map(s -> s.toLowerCase(Locale.ROOT)).collect(Collectors.joining(","))
                    + "]"
            );
        }
    }

    private final Format format;

    public GetBuiltinPrivilegesRequest(StreamInput in) throws IOException {
        super(in);
        format = in.readEnum(Format.class);
    }

    public GetBuiltinPrivilegesRequest() {
        this(Format.FLAT);
    }

    public GetBuiltinPrivilegesRequest(Format format) {
        this.format = format;
    }

    public Format getFormat() {
        return format;
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }
}
