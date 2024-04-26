/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.cluster.metadata;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexVersion;
import org.elasticsearch.index.IndexVersions;
import org.elasticsearch.index.alias.RandomAliasActionsGenerator;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.ingest.IngestMetadata;
import org.elasticsearch.test.AbstractChunkedSerializingTestCase;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.upgrades.FeatureMigrationResults;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;

public class ProjectMetadataTests extends ESTestCase {

    public void testMappingDuplication() {
        final Set<String> randomMappingDefinitions;
        {
            int numEntries = randomIntBetween(4, 8);
            randomMappingDefinitions = Sets.newHashSetWithExpectedSize(numEntries);
            for (int i = 0; i < numEntries; i++) {
                Map<String, Object> mapping = RandomAliasActionsGenerator.randomMap(2);
                String mappingAsString = Strings.toString((builder, params) -> builder.mapContents(mapping));
                randomMappingDefinitions.add(mappingAsString);
            }
        }

        final ProjectId projectId = new ProjectId(randomUUID());
        ProjectMetadata metadata;
        int numIndices = randomIntBetween(16, 32);
        {
            String[] definitions = randomMappingDefinitions.toArray(String[]::new);
            ProjectMetadata.Builder pb = ProjectMetadata.builder().id(projectId);
            for (int i = 0; i < numIndices; i++) {
                IndexMetadata.Builder indexBuilder = IndexMetadata.builder("index-" + i)
                    .settings(Settings.builder().put(IndexMetadata.SETTING_VERSION_CREATED, IndexVersion.current()))
                    .putMapping(definitions[i % randomMappingDefinitions.size()])
                    .numberOfShards(1)
                    .numberOfReplicas(0);
                if (randomBoolean()) {
                    pb.put(indexBuilder);
                } else {
                    pb.put(indexBuilder.build(), true);
                }
            }
            metadata = pb.build();
        }
        assertThat(metadata.getMappingsByHash(), aMapWithSize(randomMappingDefinitions.size()));
        assertThat(
            metadata.indices().values().stream().map(IndexMetadata::mapping).collect(Collectors.toSet()),
            hasSize(metadata.getMappingsByHash().size())
        );

        // Add a new index with a new index with known mapping:
        MappingMetadata mapping = metadata.indices().get("index-" + randomInt(numIndices - 1)).mapping();
        MappingMetadata entry = metadata.getMappingsByHash().get(mapping.getSha256());
        {
            var pb = ProjectMetadata.builder(metadata);
            pb.put(
                IndexMetadata.builder("index-" + numIndices)
                    .settings(Settings.builder().put(IndexMetadata.SETTING_VERSION_CREATED, IndexVersion.current()))
                    .putMapping(mapping)
                    .numberOfShards(1)
                    .numberOfReplicas(0)
            );
            metadata = pb.build();
        }
        assertThat(metadata.getMappingsByHash(), aMapWithSize(randomMappingDefinitions.size()));
        assertThat(metadata.getMappingsByHash().get(mapping.getSha256()), equalTo(entry));

        // Remove index and ensure mapping cache stays the same
        {
            var pb = ProjectMetadata.builder(metadata);
            pb.remove("index-" + numIndices);
            metadata = pb.build();
        }
        assertThat(metadata.getMappingsByHash(), aMapWithSize(randomMappingDefinitions.size()));
        assertThat(metadata.getMappingsByHash().get(mapping.getSha256()), equalTo(entry));

        // Update a mapping of an index:
        IndexMetadata luckyIndex = metadata.index("index-" + randomInt(numIndices - 1));
        entry = metadata.getMappingsByHash().get(luckyIndex.mapping().getSha256());
        MappingMetadata updatedMapping = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, Map.of("mapping", "updated"));
        {
            var pb = ProjectMetadata.builder(metadata);
            pb.put(IndexMetadata.builder(luckyIndex).putMapping(updatedMapping));
            metadata = pb.build();
        }
        assertThat(metadata.getMappingsByHash(), aMapWithSize(randomMappingDefinitions.size() + 1));
        assertThat(metadata.getMappingsByHash().get(luckyIndex.mapping().getSha256()), equalTo(entry));
        assertThat(metadata.getMappingsByHash().get(updatedMapping.getSha256()), equalTo(updatedMapping));

        // Remove the index with updated mapping
        {
            var pb = ProjectMetadata.builder(metadata);
            pb.remove(luckyIndex.getIndex().getName());
            metadata = pb.build();
        }
        assertThat(metadata.getMappingsByHash(), aMapWithSize(randomMappingDefinitions.size()));
        assertThat(metadata.getMappingsByHash().get(updatedMapping.getSha256()), nullValue());

        // Add an index with new mapping and then later remove it:
        MappingMetadata newMapping = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, Map.of("new", "mapping"));
        {
            var pb = ProjectMetadata.builder(metadata);
            pb.put(
                IndexMetadata.builder("index-" + numIndices)
                    .settings(Settings.builder().put(IndexMetadata.SETTING_VERSION_CREATED, IndexVersion.current()))
                    .putMapping(newMapping)
                    .numberOfShards(1)
                    .numberOfReplicas(0)
            );
            metadata = pb.build();
        }
        assertThat(metadata.getMappingsByHash(), aMapWithSize(randomMappingDefinitions.size() + 1));
        assertThat(metadata.getMappingsByHash().get(newMapping.getSha256()), equalTo(newMapping));

        {
            var pb = ProjectMetadata.builder(metadata);
            pb.remove("index-" + numIndices);
            metadata = pb.build();
        }
        assertThat(metadata.getMappingsByHash(), aMapWithSize(randomMappingDefinitions.size()));
        assertThat(metadata.getMappingsByHash().get(newMapping.getSha256()), nullValue());
    }

    public void testOldestIndexComputation() {
        ProjectMetadata metadata = buildIndicesWithVersions(
            IndexVersions.V_7_0_0,
            IndexVersion.current(),
            IndexVersion.fromId(IndexVersion.current().id() + 1)
        ).build();

        assertEquals(IndexVersions.V_7_0_0, metadata.oldestIndexVersion());

        ProjectMetadata.Builder b = ProjectMetadata.builder().generateProjectIdIfNeeded();
        assertEquals(IndexVersion.current(), b.build().oldestIndexVersion());

        Throwable ex = expectThrows(
            IllegalArgumentException.class,
            () -> buildIndicesWithVersions(IndexVersions.V_7_0_0, IndexVersions.ZERO, IndexVersion.fromId(IndexVersion.current().id() + 1))
                .build()
        );

        assertEquals("[index.version.created] is not present in the index settings for index with UUID [null]", ex.getMessage());
    }

    public void testChunkedToXContent() {
        AbstractChunkedSerializingTestCase.assertChunkCount(emptyMetadata(), ProjectMetadataTests::expectedChunkCount);
        AbstractChunkedSerializingTestCase.assertChunkCount(
            randomMetadata(randomInt(10)).build(),
            ProjectMetadataTests::expectedChunkCount
        );
    }

    private static ProjectMetadata emptyMetadata() {
        return ProjectMetadata.builder().generateProjectIdIfNeeded().build();
    }

    static ProjectMetadata.Builder randomMetadata(int numDataStreams) {
        ProjectMetadata.Builder builder = ProjectMetadata.builder()
            .generateProjectIdIfNeeded()
            .put(buildIndexMetadata("index", "alias", randomBoolean() ? null : randomBoolean()).build(), randomBoolean())
            .put(
                IndexTemplateMetadata.builder("template" + randomAlphaOfLength(3))
                    .patterns(Arrays.asList("bar-*", "foo-*"))
                    .settings(Settings.builder().put("random_index_setting_" + randomAlphaOfLength(3), randomAlphaOfLength(5)).build())
                    .build()
            )
            .indexGraveyard(IndexGraveyardTests.createRandom())
            .put("component_template_" + randomAlphaOfLength(3), ComponentTemplateTests.randomInstance())
            .put("index_template_v2_" + randomAlphaOfLength(3), ComposableIndexTemplateTests.randomInstance());

        for (int k = 0; k < numDataStreams; k++) {
            DataStream randomDataStream = DataStreamTestHelper.randomInstance();
            for (Index index : randomDataStream.getIndices()) {
                builder.put(DataStreamTestHelper.getIndexMetadataBuilderForIndex(index));
            }
            builder.put(randomDataStream);
        }

        return builder;
    }

    private ProjectMetadata.Builder buildIndicesWithVersions(IndexVersion... indexVersions) {
        int lastIndexNum = randomIntBetween(9, 50);
        ProjectMetadata.Builder builder = ProjectMetadata.builder().generateProjectIdIfNeeded();
        for (IndexVersion indexVersion : indexVersions) {
            IndexMetadata im = IndexMetadata.builder(DataStream.getDefaultBackingIndexName("index", lastIndexNum))
                .settings(settings(indexVersion))
                .numberOfShards(1)
                .numberOfReplicas(1)
                .build();
            builder.put(im, false);
            lastIndexNum = randomIntBetween(lastIndexNum + 1, lastIndexNum + 50);
        }

        return builder;
    }

    private static IndexMetadata.Builder buildIndexMetadata(String name, String alias, Boolean writeIndex) {
        return IndexMetadata.builder(name)
            .settings(settings(IndexVersion.current()))
            .creationDate(randomNonNegativeLong())
            .putAlias(AliasMetadata.builder(alias).writeIndex(writeIndex))
            .numberOfShards(1)
            .numberOfReplicas(0);
    }

    public static int expectedChunkCount(ProjectMetadata metadata) {
        int open = 1;
        int id = 1;
        long indices = 2 + metadata.indices().size(); // start, body, end
        int customs = 0; // calculated below
        long templates = 2 + metadata.templates().size(); // start, body, end
        long close = 1;

        for (var custom : metadata.customs().values()) {
            customs += 2; // open/close
            if (custom instanceof ComponentTemplateMetadata componentTemplateMetadata) {
                customs += 2 + componentTemplateMetadata.componentTemplates().size();
            } else if (custom instanceof ComposableIndexTemplateMetadata composableIndexTemplateMetadata) {
                customs += 2 + composableIndexTemplateMetadata.indexTemplates().size();
            } else if (custom instanceof DataStreamMetadata dataStreamMetadata) {
                customs += 4 + dataStreamMetadata.dataStreams().size() + dataStreamMetadata.getDataStreamAliases().size();
            } else if (custom instanceof FeatureMigrationResults featureMigrationResults) {
                customs += 2 + featureMigrationResults.getFeatureStatuses().size();

            } else if (custom instanceof IndexGraveyard indexGraveyard) {
                customs += 2 + indexGraveyard.getTombstones().size();
            } else if (custom instanceof IngestMetadata ingestMetadata) {
                customs += 2 + ingestMetadata.getPipelines().size();
            } else {
                throw new IllegalStateException("Unexpected custom type: " + custom);
            }
        }

        return Math.toIntExact(open + id + indices + customs + templates + close);
    }

}
