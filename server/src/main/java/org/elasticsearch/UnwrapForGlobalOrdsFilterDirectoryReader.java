/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch;

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FilterDirectoryReader;

import java.io.IOException;

public abstract class UnwrapForGlobalOrdsFilterDirectoryReader extends FilterDirectoryReader {

    /**
     * Create a new FilterDirectoryReader that filters a passed in DirectoryReader,
     * using the supplied SubReaderWrapper to wrap its subreader.
     *
     * @param in      the DirectoryReader to filter
     * @param wrapper the SubReaderWrapper to use to wrap subreaders
     */
    public UnwrapForGlobalOrdsFilterDirectoryReader(DirectoryReader in, SubReaderWrapper wrapper) throws IOException {
        super(in, wrapper);
    }

    public static DirectoryReader unwrapOnce(UnwrapForGlobalOrdsFilterDirectoryReader reader) {
        return reader.getDelegate();
    }
}
