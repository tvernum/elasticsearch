/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.cluster.metadata;

import org.elasticsearch.TransportVersion;
import org.elasticsearch.TransportVersions;
import org.elasticsearch.cluster.Diff;
import org.elasticsearch.cluster.Diffable;
import org.elasticsearch.cluster.DiffableUtils;
import org.elasticsearch.cluster.NamedDiffableValueSerializer;
import org.elasticsearch.cluster.SimpleDiffable;
import org.elasticsearch.cluster.coordination.CoordinationMetadata;
import org.elasticsearch.cluster.coordination.PublicationTransportHandler;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Iterators;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.VersionedNamedWriteable;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.ChunkedToXContentHelper;
import org.elasticsearch.xcontent.ToXContent;

import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;

import static org.elasticsearch.common.settings.Settings.readSettingsFromStream;

public class ClusterMetadata implements Diffable<ClusterMetadata> {

    public interface ClusterCustom extends Metadata.Custom<ClusterCustom> {}

    private static final NamedDiffableValueSerializer<ClusterCustom> CUSTOM_VALUE_SERIALIZER = new NamedDiffableValueSerializer<>(
        ClusterCustom.class
    );

    private final String clusterUUID;
    private final boolean clusterUUIDCommitted;

    private final CoordinationMetadata coordinationMetadata;

    private final Settings transientSettings;
    private final Settings persistentSettings;
    private final Settings settings;
    private final DiffableStringMap hashesOfConsistentSettings;

    private final ImmutableOpenMap<String, ClusterCustom> customs;

    public ClusterMetadata(
        String clusterUUID,
        boolean clusterUUIDCommitted,
        CoordinationMetadata coordinationMetadata,
        Settings transientSettings,
        Settings persistentSettings,
        Settings settings,
        DiffableStringMap hashesOfConsistentSettings,
        ImmutableOpenMap<String, ClusterCustom> customs
    ) {
        this.clusterUUID = clusterUUID;
        this.clusterUUIDCommitted = clusterUUIDCommitted;
        this.coordinationMetadata = coordinationMetadata;
        this.transientSettings = transientSettings;
        this.persistentSettings = persistentSettings;
        this.settings = settings;
        this.hashesOfConsistentSettings = hashesOfConsistentSettings;
        this.customs = customs;
    }

    public ClusterMetadata(
        String clusterUUID,
        boolean clusterUUIDCommitted,
        CoordinationMetadata coordinationMetadata,
        Settings transientSettings,
        Settings persistentSettings,
        DiffableStringMap hashesOfConsistentSettings,
        ImmutableOpenMap<String, ClusterCustom> customs
    ) {
        this(
            clusterUUID,
            clusterUUIDCommitted,
            coordinationMetadata,
            transientSettings,
            persistentSettings,
            Settings.builder().put(persistentSettings).put(transientSettings).build(),
            hashesOfConsistentSettings,
            customs
        );
    }

    public ClusterMetadata copy() {
        return new ClusterMetadata(
            clusterUUID,
            clusterUUIDCommitted,
            coordinationMetadata,
            transientSettings,
            persistentSettings,
            settings,
            hashesOfConsistentSettings,
            customs
        );
    }

    public ClusterMetadata withCoordinationMetadata(CoordinationMetadata coordinationMetadata) {
        return new ClusterMetadata(
            clusterUUID,
            clusterUUIDCommitted,
            coordinationMetadata,
            transientSettings,
            persistentSettings,
            settings,
            hashesOfConsistentSettings,
            customs
        );
    }

    public ClusterMetadata withLastCommittedValues(
        boolean clusterUUIDCommitted,
        CoordinationMetadata.VotingConfiguration lastCommittedConfiguration
    ) {
        if (clusterUUIDCommitted == this.clusterUUIDCommitted
            && lastCommittedConfiguration.equals(this.coordinationMetadata.getLastCommittedConfiguration())) {
            return this;
        }
        return new ClusterMetadata(
            clusterUUID,
            clusterUUIDCommitted,
            CoordinationMetadata.builder(coordinationMetadata).lastCommittedConfiguration(lastCommittedConfiguration).build(),
            transientSettings,
            persistentSettings,
            settings,
            hashesOfConsistentSettings,
            customs
        );
    }

    @SuppressWarnings("unchecked")
    public <T extends ClusterCustom> T custom(String type) {
        return (T) customs.get(type);
    }

    @SuppressWarnings("unchecked")
    public <T extends ClusterCustom> T custom(String type, T defaultValue) {
        return (T) customs.getOrDefault(type, defaultValue);
    }

    public String clusterUUID() {
        return this.clusterUUID;
    }

    /**
     * Whether the current node with the given cluster state is locked into the cluster with the UUID returned by {@link #clusterUUID()},
     * meaning that it will not accept any cluster state with a different clusterUUID.
     */
    public boolean clusterUUIDCommitted() {
        return this.clusterUUIDCommitted;
    }

    /**
     * Returns the merged transient and persistent settings.
     */
    public Settings settings() {
        return this.settings;
    }

    public Settings transientSettings() {
        return this.transientSettings;
    }

    public Settings persistentSettings() {
        return this.persistentSettings;
    }

    public Map<String, String> hashesOfConsistentSettings() {
        return this.hashesOfConsistentSettings;
    }

    // Package protected, Metadata.Builder needs access
    DiffableStringMap diffableHashesOfConsistentSettings() {
        return this.hashesOfConsistentSettings;
    }

    Map<String, ClusterCustom> customs() {
        return customs;
    }

    public CoordinationMetadata coordinationMetadata() {
        return this.coordinationMetadata;
    }

    public NodesShutdownMetadata nodeShutdowns() {
        return custom(NodesShutdownMetadata.TYPE, NodesShutdownMetadata.EMPTY);
    }

    public static boolean isGlobalStateEquals(ClusterMetadata metadata1, ClusterMetadata metadata2) {
        if (metadata1.coordinationMetadata.equals(metadata2.coordinationMetadata) == false) {
            return false;
        }
        if (metadata1.persistentSettings.equals(metadata2.persistentSettings) == false) {
            return false;
        }
        if (metadata1.hashesOfConsistentSettings.equals(metadata2.hashesOfConsistentSettings) == false) {
            return false;
        }
        if (metadata1.clusterUUID.equals(metadata2.clusterUUID) == false) {
            return false;
        }
        if (metadata1.clusterUUIDCommitted != metadata2.clusterUUIDCommitted) {
            return false;
        }
        // Check if any persistent metadata needs to be saved
        int customCount1 = 0;
        for (Map.Entry<String, ClusterCustom> cursor : metadata1.customs.entrySet()) {
            if (cursor.getValue().context().contains(Metadata.XContentContext.GATEWAY)) {
                if (cursor.getValue().equals(metadata2.custom(cursor.getKey())) == false) {
                    return false;
                }
                customCount1++;
            }
        }
        int customCount2 = 0;
        for (var custom : metadata2.customs.values()) {
            if (custom.context().contains(Metadata.XContentContext.GATEWAY)) {
                customCount2++;
            }
        }
        if (customCount1 != customCount2) {
            return false;
        }
        return true;
    }

    @Override
    public Diff<ClusterMetadata> diff(ClusterMetadata previousState) {
        return new ClusterMetadataDiff(previousState, this);
    }

    public static Diff<ClusterMetadata> readDiffFrom(StreamInput in) throws IOException {
        final boolean empty = in.readBoolean();
        return empty ? SimpleDiffable.empty() : new ClusterMetadataDiff(in);
    }

    private static class ClusterMetadataDiff implements Diff<ClusterMetadata> {

        private static final TransportVersion NOOP_METADATA_DIFF_VERSION = TransportVersions.V_8_5_0;
        private static final TransportVersion NOOP_METADATA_DIFF_SAFE_VERSION =
            PublicationTransportHandler.INCLUDES_LAST_COMMITTED_DATA_VERSION;

        private final String clusterUUID;
        private final boolean clusterUUIDCommitted;
        private final CoordinationMetadata coordinationMetadata;
        private final Settings transientSettings;
        private final Settings persistentSettings;
        private final Diff<DiffableStringMap> hashesOfConsistentSettings;
        private final Diff<ImmutableOpenMap<String, ClusterCustom>> customs;

        /**
         * true if this diff is a noop because before and after were the same instance
         */
        private final boolean empty;

        ClusterMetadataDiff(ClusterMetadata before, ClusterMetadata after) {
            this.empty = before == after;
            clusterUUID = after.clusterUUID;
            clusterUUIDCommitted = after.clusterUUIDCommitted;
            coordinationMetadata = after.coordinationMetadata;
            transientSettings = after.transientSettings;
            persistentSettings = after.persistentSettings;
            if (empty) {
                hashesOfConsistentSettings = DiffableStringMap.DiffableStringMapDiff.EMPTY;
                customs = DiffableUtils.emptyDiff();
            } else {
                hashesOfConsistentSettings = after.hashesOfConsistentSettings.diff(before.hashesOfConsistentSettings);
                customs = DiffableUtils.diff(
                    before.customs,
                    after.customs,
                    DiffableUtils.getStringKeySerializer(),
                    CUSTOM_VALUE_SERIALIZER
                );
            }
        }

        private ClusterMetadataDiff(StreamInput in) throws IOException {
            // TODO[MultiProject] support serializing in old format
            empty = false;
            clusterUUID = in.readString();
            clusterUUIDCommitted = in.readBoolean();
            coordinationMetadata = new CoordinationMetadata(in);
            transientSettings = Settings.readSettingsFromStream(in);
            persistentSettings = Settings.readSettingsFromStream(in);
            if (in.getTransportVersion().onOrAfter(TransportVersions.V_7_3_0)) {
                hashesOfConsistentSettings = DiffableStringMap.readDiffFrom(in);
            } else {
                hashesOfConsistentSettings = DiffableStringMap.DiffableStringMapDiff.EMPTY;
            }
            customs = DiffableUtils.readImmutableOpenMapDiff(in, DiffableUtils.getStringKeySerializer(), CUSTOM_VALUE_SERIALIZER);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeBoolean(empty);
            if (empty) {
                // noop diff
                return;
            }
            out.writeString(clusterUUID);
            out.writeBoolean(clusterUUIDCommitted);
            coordinationMetadata.writeTo(out);
            transientSettings.writeTo(out);
            persistentSettings.writeTo(out);
            if (out.getTransportVersion().onOrAfter(TransportVersions.V_7_3_0)) {
                hashesOfConsistentSettings.writeTo(out);
            }
            customs.writeTo(out);
        }

        @Override
        public ClusterMetadata apply(ClusterMetadata part) {
            if (empty) {
                return part;
            }
            // @TODO[MultiProject] Should this use the builder?
            return new ClusterMetadata(
                clusterUUID,
                clusterUUIDCommitted,
                coordinationMetadata,
                transientSettings,
                persistentSettings,
                hashesOfConsistentSettings.apply(part.hashesOfConsistentSettings),
                customs.apply(part.customs)
            );
        }
    }

    public static final TransportVersion MAPPINGS_AS_HASH_VERSION = TransportVersions.V_8_1_0;

    public static ClusterMetadata readFrom(StreamInput in) throws IOException {
        // TODO[MultiProject] support reading from old format (or will Metadata do that)
        var clusterUUID = in.readString();
        var clusterUUIDCommitted = in.readBoolean();
        var coordinationMetadata = new CoordinationMetadata(in);
        var transientSettings = readSettingsFromStream(in);
        var persistentSettings = readSettingsFromStream(in);
        var hashesOfConsistentSettings = DiffableStringMap.readFrom(in);

        int customSize = in.readVInt();
        final ImmutableOpenMap.Builder<String, ClusterCustom> customs = ImmutableOpenMap.<String, ClusterCustom>builder(customSize);
        for (int i = 0; i < customSize; i++) {
            ClusterCustom customIndexMetadata = in.readNamedWriteable(ClusterCustom.class);
            customs.put(customIndexMetadata.getWriteableName(), customIndexMetadata);
        }

        return new ClusterMetadata(
            clusterUUID,
            clusterUUIDCommitted,
            coordinationMetadata,
            transientSettings,
            persistentSettings,
            hashesOfConsistentSettings,
            customs.build()
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        // TODO[MultiProject] support serializing in old format
        out.writeString(clusterUUID);
        out.writeBoolean(clusterUUIDCommitted);
        coordinationMetadata.writeTo(out);
        transientSettings.writeTo(out);
        persistentSettings.writeTo(out);
        hashesOfConsistentSettings.writeTo(out);
        VersionedNamedWriteable.writeVersionedWritables(out, customs);
    }

    public Iterator<? extends ToXContent> toXContentChunked(ToXContent.Params p, Metadata.XContentContext context) {
        final Iterator<? extends ToXContent> persistentSettings = context != Metadata.XContentContext.API
            && this.persistentSettings.isEmpty() == false ? Iterators.single((builder, params) -> {
                builder.startObject("settings");
                persistentSettings().toXContent(builder, new ToXContent.MapParams(Collections.singletonMap("flat_settings", "true")));
                return builder.endObject();
            }) : Collections.emptyIterator();

        final Iterator<ToXContent> main = Iterators.single((builder, params) -> {
            builder.field("cluster_uuid", clusterUUID);
            builder.field("cluster_uuid_committed", clusterUUIDCommitted);
            builder.startObject("cluster_coordination");
            coordinationMetadata().toXContent(builder, params);
            return builder.endObject();
        });
        final Iterator<ToXContent> customs = Iterators.flatMap(
            this.customs.entrySet().iterator(),
            entry -> entry.getValue().context().contains(context)
                ? ChunkedToXContentHelper.wrapWithObject(entry.getKey(), entry.getValue().toXContentChunked(p))
                : Collections.emptyIterator()
        );
        return Iterators.concat(main, persistentSettings, customs);
    }

}
