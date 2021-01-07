/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action.secret;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.SecureString;

import java.io.IOException;

import static org.elasticsearch.action.ValidateActions.addValidationError;

/**
 * Request class used for the creation of stored secrets.
 */
public final class RetrieveSecretRequest extends ActionRequest {

    private final String namespace;
    private final String id;
    private final SecureString password;

    public RetrieveSecretRequest(String namespace, String id, SecureString password) {
        this.namespace = namespace;
        this.id = id;
        this.password = password;
    }

    public RetrieveSecretRequest(StreamInput in) throws IOException {
        super(in);
        this.namespace = in.readString();
        this.id = in.readString();
        this.password = in.readSecureString();
    }

    public String getNamespace() {
        return namespace;
    }

    public String getId() {
        return id;
    }

    public SecureString getPassword() {
        return password;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (Strings.isNullOrEmpty(namespace)) {
            validationException = addValidationError("secret namespace is required", validationException);
        }
        if (Strings.isNullOrEmpty(id)) {
            validationException = addValidationError("secret id is required", validationException);
        }
        if (password == null || password.length() < 8) {
            validationException = addValidationError("secret must be at least 8 characters long", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(namespace);
        out.writeString(id);
        out.writeSecureString(password);
    }
}
