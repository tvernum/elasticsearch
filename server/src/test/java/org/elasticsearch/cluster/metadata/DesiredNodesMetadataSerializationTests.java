/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.cluster.metadata;

import org.elasticsearch.cluster.Diff;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.test.ChunkedToXContentDiffableSerializationTestCase;
import org.elasticsearch.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collections;

import static org.elasticsearch.cluster.metadata.DesiredNodesSerializationTests.mutateDesiredNodes;
import static org.elasticsearch.cluster.metadata.DesiredNodesTestCase.randomDesiredNodes;

public class DesiredNodesMetadataSerializationTests extends ChunkedToXContentDiffableSerializationTestCase<ClusterMetadata.ClusterCustom> {
    @Override
    protected ClusterMetadata.ClusterCustom makeTestChanges(ClusterMetadata.ClusterCustom testInstance) {
        if (randomBoolean()) {
            return testInstance;
        }
        return mutate((DesiredNodesMetadata) testInstance);
    }

    @Override
    protected Writeable.Reader<Diff<ClusterMetadata.ClusterCustom>> diffReader() {
        return DesiredNodesMetadata::readDiffFrom;
    }

    @Override
    protected ClusterMetadata.ClusterCustom doParseInstance(XContentParser parser) throws IOException {
        return DesiredNodesMetadata.fromXContent(parser);
    }

    @Override
    protected Writeable.Reader<ClusterMetadata.ClusterCustom> instanceReader() {
        return DesiredNodesMetadata::new;
    }

    @Override
    protected NamedWriteableRegistry getNamedWriteableRegistry() {
        return new NamedWriteableRegistry(
            Collections.singletonList(
                new NamedWriteableRegistry.Entry(ClusterMetadata.ClusterCustom.class, DesiredNodesMetadata.TYPE, DesiredNodesMetadata::new)
            )
        );
    }

    @Override
    protected ClusterMetadata.ClusterCustom createTestInstance() {
        return randomDesiredNodesMetadata();
    }

    @Override
    protected ClusterMetadata.ClusterCustom mutateInstance(ClusterMetadata.ClusterCustom instance) {
        return null;// TODO implement https://github.com/elastic/elasticsearch/issues/25929
    }

    private static DesiredNodesMetadata randomDesiredNodesMetadata() {
        return new DesiredNodesMetadata(randomDesiredNodes());
    }

    private DesiredNodesMetadata mutate(DesiredNodesMetadata base) {
        return new DesiredNodesMetadata(mutateDesiredNodes(base.getLatestDesiredNodes()));
    }
}
