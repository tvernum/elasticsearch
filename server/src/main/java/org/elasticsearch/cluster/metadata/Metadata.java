/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.cluster.metadata;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.TransportVersion;
import org.elasticsearch.TransportVersions;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.Diff;
import org.elasticsearch.cluster.Diffable;
import org.elasticsearch.cluster.DiffableUtils;
import org.elasticsearch.cluster.NamedDiffable;
import org.elasticsearch.cluster.SimpleDiffable;
import org.elasticsearch.cluster.block.ClusterBlock;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.coordination.CoordinationMetadata;
import org.elasticsearch.cluster.coordination.PublicationTransportHandler;
import org.elasticsearch.cluster.routing.RoutingTable;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Iterators;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.Maps;
import org.elasticsearch.common.xcontent.ChunkedToXContent;
import org.elasticsearch.common.xcontent.ChunkedToXContentHelper;
import org.elasticsearch.common.xcontent.XContentParserUtils;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.gateway.MetadataStateFormat;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.index.IndexVersion;
import org.elasticsearch.plugins.MapperPlugin;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.xcontent.NamedObjectNotFoundException;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xcontent.ToXContent;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedMap;
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@link Metadata} is the part of the {@link ClusterState} which persists across restarts. This persistence is XContent-based, so a
 * round-trip through XContent must be faithful in {@link XContentContext#GATEWAY} context.
 * <p>
 * The details of how this is persisted are covered in {@link org.elasticsearch.gateway.PersistedClusterStateService}.
 * </p>
 */
public class Metadata implements Iterable<IndexMetadata>, Diffable<Metadata>, ChunkedToXContent {

    private static final Logger logger = LogManager.getLogger(Metadata.class);

    public static final Runnable ON_NEXT_INDEX_FIND_MAPPINGS_NOOP = () -> {};
    public static final String ALL = "_all";
    public static final String UNKNOWN_CLUSTER_UUID = "_na_";

    public enum XContentContext {
        /* Custom metadata should be returned as part of API call */
        API,

        /* Custom metadata should be stored as part of the persistent cluster state */
        GATEWAY,

        /* Custom metadata should be stored as part of a snapshot */
        SNAPSHOT;

        public static XContentContext from(ToXContent.Params params) {
            return valueOf(params.param(CONTEXT_MODE_PARAM, CONTEXT_MODE_API));
        }
    }

    /**
     * Indicates that this custom metadata will be returned as part of an API call but will not be persisted
     */
    public static EnumSet<XContentContext> API_ONLY = EnumSet.of(XContentContext.API);

    /**
     * Indicates that this custom metadata will be returned as part of an API call and will be persisted between
     * node restarts, but will not be a part of a snapshot global state
     */
    public static EnumSet<XContentContext> API_AND_GATEWAY = EnumSet.of(XContentContext.API, XContentContext.GATEWAY);

    /**
     * Indicates that this custom metadata will be returned as part of an API call and stored as a part of
     * a snapshot global state, but will not be persisted between node restarts
     */
    public static EnumSet<XContentContext> API_AND_SNAPSHOT = EnumSet.of(XContentContext.API, XContentContext.SNAPSHOT);

    /**
     * Indicates that this custom metadata will be returned as part of an API call, stored as a part of
     * a snapshot global state, and will be persisted between node restarts
     */
    public static EnumSet<XContentContext> ALL_CONTEXTS = EnumSet.allOf(XContentContext.class);

    /**
     * Custom metadata that persists (via XContent) across restarts. The deserialization method for each implementation must be registered
     * with the {@link NamedXContentRegistry}.
     */
    public interface Custom<C extends Custom<?>> extends NamedDiffable<C>, ChunkedToXContent {

        EnumSet<XContentContext> context();

        /**
         * @return true if this custom could be restored from snapshot
         */
        default boolean isRestorable() {
            return context().contains(XContentContext.SNAPSHOT);
        }
    }

    public static final Setting<Boolean> SETTING_READ_ONLY_SETTING = Setting.boolSetting(
        "cluster.blocks.read_only",
        false,
        Property.Dynamic,
        Property.NodeScope
    );

    public static final ClusterBlock CLUSTER_READ_ONLY_BLOCK = new ClusterBlock(
        6,
        "cluster read-only (api)",
        false,
        false,
        false,
        RestStatus.FORBIDDEN,
        EnumSet.of(ClusterBlockLevel.WRITE, ClusterBlockLevel.METADATA_WRITE)
    );

    public static final Setting<Boolean> SETTING_READ_ONLY_ALLOW_DELETE_SETTING = Setting.boolSetting(
        "cluster.blocks.read_only_allow_delete",
        false,
        Property.Dynamic,
        Property.NodeScope
    );

    public static final ClusterBlock CLUSTER_READ_ONLY_ALLOW_DELETE_BLOCK = new ClusterBlock(
        13,
        "cluster read-only / allow delete (api)",
        false,
        false,
        true,
        RestStatus.FORBIDDEN,
        EnumSet.of(ClusterBlockLevel.WRITE, ClusterBlockLevel.METADATA_WRITE)
    );

    public static final Metadata EMPTY_METADATA = builder().build();

    public static final String CONTEXT_MODE_PARAM = "context_mode";

    public static final String CONTEXT_MODE_SNAPSHOT = XContentContext.SNAPSHOT.toString();

    public static final String CONTEXT_MODE_GATEWAY = XContentContext.GATEWAY.toString();

    public static final String CONTEXT_MODE_API = XContentContext.API.toString();

    public static final String DEDUPLICATED_MAPPINGS_PARAM = "deduplicated_mappings";
    public static final String GLOBAL_STATE_FILE_PREFIX = "global-";

    private final long version;
    private final ClusterMetadata clusterMetadata;
    private final Map<ProjectId, ProjectMetadata> projects;

    // @TODO[MultiProject]: Does this belong in ClusterMetadata or ProjectMetadata, or do we need to split it?
    private final Map<String, ReservedStateMetadata> reservedStateMetadata;

    private Metadata(
        long version,
        ClusterMetadata clusterMetadata,
        Map<ProjectId, ProjectMetadata> projects,
        Map<String, ReservedStateMetadata> reservedStateMetadata
    ) {
        this.clusterMetadata = clusterMetadata;
        this.projects = projects;
        this.version = version;
        this.reservedStateMetadata = reservedStateMetadata;
        assert assertConsistent();
    }

    @Deprecated
    private Metadata(
        String clusterUUID,
        boolean clusterUUIDCommitted,
        long version,
        CoordinationMetadata coordinationMetadata,
        Settings transientSettings,
        Settings persistentSettings,
        Settings settings,
        DiffableStringMap hashesOfConsistentSettings,
        int totalNumberOfShards,
        int totalOpenIndexShards,
        ImmutableOpenMap<String, IndexMetadata> indices,
        ImmutableOpenMap<String, Set<Index>> aliasedIndices,
        ImmutableOpenMap<String, IndexTemplateMetadata> templates,
        ImmutableOpenMap<String, Custom<?>> customs,
        String[] allIndices,
        String[] visibleIndices,
        String[] allOpenIndices,
        String[] visibleOpenIndices,
        String[] allClosedIndices,
        String[] visibleClosedIndices,
        SortedMap<String, IndexAbstraction> indicesLookup,
        Map<String, MappingMetadata> mappingsByHash,
        IndexVersion oldestIndexVersion,
        Map<String, ReservedStateMetadata> reservedStateMetadata
    ) {
        ImmutableOpenMap<String, ClusterMetadata.ClusterCustom> clusterCustoms = ImmutableOpenMap.builder(
            customs.entrySet()
                .stream()
                .filter(e -> e.getValue() instanceof ClusterMetadata.ClusterCustom)
                .collect(Collectors.toMap(Map.Entry::getKey, e -> (ClusterMetadata.ClusterCustom) e.getValue()))
        ).build();
        ImmutableOpenMap<String, ProjectMetadata.ProjectCustom> projectCustoms = ImmutableOpenMap.builder(
            customs.entrySet()
                .stream()
                .filter(e -> e.getValue() instanceof ProjectMetadata.ProjectCustom)
                .collect(Collectors.toMap(Map.Entry::getKey, e -> (ProjectMetadata.ProjectCustom) e.getValue()))
        ).build();
        this.clusterMetadata = new ClusterMetadata(
            clusterUUID,
            clusterUUIDCommitted,
            coordinationMetadata,
            transientSettings,
            persistentSettings,
            settings,
            hashesOfConsistentSettings,
            clusterCustoms
        );
        this.projects = Maps.newHashMapWithExpectedSize(1);
        final ProjectId projectId = new ProjectId(clusterUUID);
        this.projects.put(
            projectId,
            new ProjectMetadata(
                projectId,
                totalNumberOfShards,
                totalOpenIndexShards,
                indices,
                aliasedIndices,
                templates,
                projectCustoms,
                allIndices,
                visibleIndices,
                allOpenIndices,
                visibleOpenIndices,
                allClosedIndices,
                visibleClosedIndices,
                indicesLookup,
                mappingsByHash,
                oldestIndexVersion
            )
        );
        this.version = version;
        this.reservedStateMetadata = reservedStateMetadata;
        assert assertConsistent();
    }

    private boolean assertConsistent() {
        return this.projects.values().stream().allMatch(ProjectMetadata::assertConsistent);
    }

    public Metadata withIncrementedVersion() {
        // @TODO[MultiProject]: We copy the nested metadata here to retain old semantics, but do we need to?
        // We don't do it for reservedStateMetadata
        return new Metadata(version + 1, clusterMetadata.copy(), Maps.copyOf(projects, ProjectMetadata::copy), reservedStateMetadata);
    }

    public ProjectId currentProjectId() {
        // @TODO[MultiProject]: This should look at ThreadContext, but do we want Metadata to do that?
        // Maybe we can plug in a resolving function?
        // Or maybe we don't really need this
        if (projects.isEmpty()) {
            throw new IllegalStateException("Cluster has no projects");
        }
        if (projects.size() > 1) {
            throw new IllegalStateException(
                "Cluster has multiple projects (and we don't have support for picking the 'active' project yet)"
            );
        }
        return projects.keySet().iterator().next();
    }

    public ProjectMetadata project() {
        return Objects.requireNonNull(project(currentProjectId()));
    }

    public ProjectMetadata project(ProjectId projectId) {
        final ProjectMetadata project = projects.get(projectId);
        return project;
    }

    public Collection<ProjectMetadata> projects() {
        // @TODO Make the map Immutable so this isn't needed
        return Collections.unmodifiableCollection(projects.values());
    }

    private Metadata withProjectUpdate(Function<ProjectMetadata, ProjectMetadata> update) {
        var before = project();
        var after = update.apply(before);
        if (before == after) {
            return this;
        } else {
            var projectsCopy = new HashMap<>(projects);
            projectsCopy.put(after.id(), after);
            return new Metadata(version, clusterMetadata, projectsCopy, reservedStateMetadata);
        }
    }

    /**
     * Given an index and lifecycle state, returns a metadata where the lifecycle state will be
     * associated with the given index.
     * <p>
     * The passed-in index must already be present in the cluster state, this method cannot
     * be used to add an index.
     *
     * @param index          A non-null index
     * @param lifecycleState A non-null lifecycle execution state
     * @return a <code>Metadata</code> instance where the index has the provided lifecycle state
     */
    public Metadata withLifecycleState(final Index index, final LifecycleExecutionState lifecycleState) {
        return withProjectUpdate(project -> project.withLifecycleState(index, lifecycleState));
    }

    public Metadata withIndexSettingsUpdates(final Map<Index, Settings> updates) {
        return withProjectUpdate(project -> project.withIndexSettingsUpdates(updates));
    }

    public Metadata withCoordinationMetadata(CoordinationMetadata coordinationMetadata) {
        return new Metadata(version, clusterMetadata.withCoordinationMetadata(coordinationMetadata), projects, reservedStateMetadata);
    }

    public Metadata withLastCommittedValues(
        boolean clusterUUIDCommitted,
        CoordinationMetadata.VotingConfiguration lastCommittedConfiguration
    ) {
        return new Metadata(
            version,
            clusterMetadata.withLastCommittedValues(clusterUUIDCommitted, lastCommittedConfiguration),
            projects,
            reservedStateMetadata
        );
    }

    /**
     * Creates a copy of this instance updated with the given {@link IndexMetadata} that must only contain changes to primary terms
     * and in-sync allocation ids relative to the existing entries. This method is only used by
     * {@link org.elasticsearch.cluster.routing.allocation.IndexMetadataUpdater#applyChanges(Metadata, RoutingTable)}.
     *
     * @param updates map of index name to {@link IndexMetadata}.
     * @return updated metadata instance
     */
    public Metadata withAllocationAndTermUpdatesOnly(Map<String, IndexMetadata> updates) {
        return withProjectUpdate(project -> project.withAllocationAndTermUpdatesOnly(updates));
    }

    /**
     * Creates a copy of this instance with the given {@code index} added.
     *
     * @param index index to add
     * @return copy with added index
     */
    public Metadata withAddedIndex(IndexMetadata index) {
        return withProjectUpdate(project -> project.withAddedIndex(index));
    }

    public long version() {
        return this.version;
    }

    public String clusterUUID() {
        return clusterMetadata.clusterUUID();
    }

    /**
     * Whether the current node with the given cluster state is locked into the cluster with the UUID returned by {@link #clusterUUID()},
     * meaning that it will not accept any cluster state with a different clusterUUID.
     */
    public boolean clusterUUIDCommitted() {
        return clusterMetadata.clusterUUIDCommitted();
    }

    /**
     * Returns the merged transient and persistent settings.
     */
    public Settings settings() {
        return clusterMetadata.settings();
    }

    public Settings transientSettings() {
        return clusterMetadata.transientSettings();
    }

    public Settings persistentSettings() {
        return clusterMetadata.persistentSettings();
    }

    public Map<String, String> hashesOfConsistentSettings() {
        return clusterMetadata.hashesOfConsistentSettings();
    }

    public CoordinationMetadata coordinationMetadata() {
        return clusterMetadata.coordinationMetadata();
    }

    public IndexVersion oldestIndexVersion() {
        return project().oldestIndexVersion();
    }

    public boolean equalsAliases(ProjectMetadata other) {
        return project().equalsAliases(other);
    }

    public boolean equalsAliases(Metadata other) {
        return equalsAliases(other.projects.get(currentProjectId()));
    }

    public boolean indicesLookupInitialized() {
        return project().indicesLookupInitialized();
    }

    public SortedMap<String, IndexAbstraction> getIndicesLookup() {
        return project().getIndicesLookup();
    }

    public boolean sameIndicesLookup(ProjectMetadata other) {
        return project().sameIndicesLookup(other);
    }

    public boolean sameIndicesLookup(Metadata other) {
        return sameIndicesLookup(other.projects.get(this.currentProjectId()));
    }

    /**
     * Finds the specific index aliases that point to the requested concrete indices directly
     * or that match with the indices via wildcards.
     *
     * @param concreteIndices The concrete indices that the aliases must point to in order to be returned.
     * @return A map of index name to the list of aliases metadata. If a concrete index does not have matching
     * aliases then the result will <b>not</b> include the index's key.
     */
    public Map<String, List<AliasMetadata>> findAllAliases(final String[] concreteIndices) {
        return project().findAllAliases(concreteIndices);
    }

    /**
     * Finds the specific index aliases that match with the specified aliases directly or partially via wildcards, and
     * that point to the specified concrete indices (directly or matching indices via wildcards).
     *
     * @param aliases         The aliases to look for. Might contain include or exclude wildcards.
     * @param concreteIndices The concrete indices that the aliases must point to in order to be returned
     * @return A map of index name to the list of aliases metadata. If a concrete index does not have matching
     * aliases then the result will <b>not</b> include the index's key.
     */
    public Map<String, List<AliasMetadata>> findAliases(final String[] aliases, final String[] concreteIndices) {
        return project().findAliases(aliases, concreteIndices);
    }

    /**
     * Finds the specific data stream aliases that match with the specified aliases directly or partially via wildcards, and
     * that point to the specified data streams (directly or matching data streams via wildcards).
     *
     * @param aliases     The aliases to look for. Might contain include or exclude wildcards.
     * @param dataStreams The data streams that the aliases must point to in order to be returned
     * @return A map of data stream name to the list of DataStreamAlias objects that match. If a data stream does not have matching
     * aliases then the result will <b>not</b> include the data stream's key.
     */
    public Map<String, List<DataStreamAlias>> findDataStreamAliases(final String[] aliases, final String[] dataStreams) {
        return project().findDataStreamAliases(aliases, dataStreams);
    }

    /**
     * Finds all mappings for concrete indices. Only fields that match the provided field
     * filter will be returned (default is a predicate that always returns true, which can be
     * overridden via plugins)
     *
     * @param onNextIndex a hook that gets notified for each index that's processed
     * @see MapperPlugin#getFieldFilter()
     */
    public Map<String, MappingMetadata> findMappings(
        String[] concreteIndices,
        Function<String, ? extends Predicate<String>> fieldFilter,
        Runnable onNextIndex
    ) {
        return project().findMappings(concreteIndices, fieldFilter, onNextIndex);
    }

    /**
     * Finds the parent data streams, if any, for the specified concrete indices.
     */
    public Map<String, DataStream> findDataStreams(String... concreteIndices) {
        return project().findDataStreams(concreteIndices);
    }

    /**
     * Checks whether the provided index is a data stream.
     */
    public boolean indexIsADataStream(String indexName) {
        return project().indexIsADataStream(indexName);
    }

    /**
     * Returns all the concrete indices.
     */
    public String[] getConcreteAllIndices() {
        return project().getConcreteAllIndices();
    }

    /**
     * Returns all the concrete indices that are not hidden.
     */
    public String[] getConcreteVisibleIndices() {
        return project().getConcreteVisibleIndices();
    }

    /**
     * Returns all of the concrete indices that are open.
     */
    public String[] getConcreteAllOpenIndices() {
        return project().getConcreteAllOpenIndices();
    }

    /**
     * Returns all of the concrete indices that are open and not hidden.
     */
    public String[] getConcreteVisibleOpenIndices() {
        return project().getConcreteVisibleOpenIndices();
    }

    /**
     * Returns all of the concrete indices that are closed.
     */
    public String[] getConcreteAllClosedIndices() {
        return project().getConcreteAllClosedIndices();
    }

    /**
     * Returns all of the concrete indices that are closed and not hidden.
     */
    public String[] getConcreteVisibleClosedIndices() {
        return project().getConcreteVisibleClosedIndices();
    }

    /**
     * Returns indexing routing for the given <code>aliasOrIndex</code>. Resolves routing from the alias metadata used
     * in the write index.
     */
    public String resolveWriteIndexRouting(@Nullable String routing, String aliasOrIndex) {
        return project().resolveWriteIndexRouting(routing, aliasOrIndex);
    }

    /**
     * Returns indexing routing for the given index.
     */
    public String resolveIndexRouting(@Nullable String routing, String aliasOrIndex) {
        return project().resolveIndexRouting(routing, aliasOrIndex);
    }

    /**
     * Checks whether an index exists (as of this {@link Metadata} with the given name. Does not check aliases or data streams.
     *
     * @param index An index name that may or may not exist in the cluster.
     * @return {@code true} if a concrete index with that name exists, {@code false} otherwise.
     */
    public boolean hasIndex(String index) {
        return project().hasIndex(index);
    }

    /**
     * Checks whether an index exists. Similar to {@link Metadata#hasIndex(String)}, but ensures that the index has the same UUID as
     * the given {@link Index}.
     *
     * @param index An {@link Index} object that may or may not exist in the cluster.
     * @return {@code true} if an index exists with the same name and UUID as the given index object, {@code false} otherwise.
     */
    public boolean hasIndex(Index index) {
        return project().hasIndex(index);
    }

    /**
     * Checks whether an index abstraction (that is, index, alias, or data stream) exists (as of this {@link Metadata} with the given name.
     *
     * @param index An index name that may or may not exist in the cluster.
     * @return {@code true} if an index abstraction with that name exists, {@code false} otherwise.
     */
    public boolean hasIndexAbstraction(String index) {
        return project().hasIndexAbstraction(index);
    }

    public IndexMetadata index(String index) {
        return project().index(index);
    }

    public IndexMetadata index(Index index) {
        return project().index(index);
    }

    /**
     * Returns true iff existing index has the same {@link IndexMetadata} instance
     */
    public boolean hasIndexMetadata(final IndexMetadata indexMetadata) {
        return project().hasIndexMetadata(indexMetadata);
    }

    /**
     * Returns the {@link IndexMetadata} for this index.
     *
     * @throws IndexNotFoundException if no metadata for this index is found
     */
    public IndexMetadata getIndexSafe(Index index) {
        return project().getIndexSafe(index);
    }

    public Map<String, IndexMetadata> indices() {
        return project().indices();
    }

    public Map<String, IndexMetadata> getIndices() {
        return indices();
    }

    /**
     * Returns whether an alias exists with provided alias name.
     *
     * @param aliasName The provided alias name
     * @return whether an alias exists with provided alias name
     */
    public boolean hasAlias(String aliasName) {
        return project().hasAlias(aliasName);
    }

    /**
     * Returns all the indices that the alias with the provided alias name refers to.
     * These are aliased indices. Not that, this only return indices that have been aliased
     * and not indices that are behind a data stream or data stream alias.
     *
     * @param aliasName The provided alias name
     * @return all aliased indices by the alias with the provided alias name
     */
    public Set<Index> aliasedIndices(String aliasName) {
        return project().aliasedIndices(aliasName);
    }

    /**
     * @return the names of all indices aliases.
     */
    public Set<String> aliasedIndices() {
        return project().aliasedIndices();
    }

    public Map<String, IndexTemplateMetadata> templates() {
        return project().templates();
    }

    public Map<String, IndexTemplateMetadata> getTemplates() {
        return templates();
    }

    public Map<String, ComponentTemplate> componentTemplates() {
        return project().componentTemplates();
    }

    public Map<String, ComposableIndexTemplate> templatesV2() {
        return project().templatesV2();
    }

    public boolean isTimeSeriesTemplate(ComposableIndexTemplate indexTemplate) {
        return project().isTimeSeriesTemplate(indexTemplate);
    }

    public Map<String, DataStream> dataStreams() {
        return project().dataStreams();
    }

    public Map<String, DataStreamAlias> dataStreamAliases() {
        return project().dataStreamAliases();
    }

    /**
     * Return a map of DataStreamAlias objects by DataStream name
     *
     * @return a map of DataStreamAlias objects by DataStream name
     */
    public Map<String, List<DataStreamAlias>> dataStreamAliasesByDataStream() {
        return project().dataStreamAliasesByDataStream();
    }

    public <T extends ProjectMetadata.ProjectCustom> T projectCustom(String type) {
        return project().custom(type);
    }

    public <T extends ProjectMetadata.ProjectCustom> T projectCustom(String type, T defaultValue) {
        return project().custom(type, defaultValue);
    }

    public <T extends ClusterMetadata.ClusterCustom> T clusterCustom(String type) {
        return clusterMetadata.custom(type);
    }

    public <T extends ClusterMetadata.ClusterCustom> T clusterCustom(String type, T defaultValue) {
        return clusterMetadata.custom(type, defaultValue);
    }

    public Map<String, ClusterMetadata.ClusterCustom> customs() {
        return clusterMetadata.customs();
    }

    public NodesShutdownMetadata nodeShutdowns() {
        return clusterMetadata.nodeShutdowns();
    }

    /**
     * Indicates if the provided index is managed by ILM. This takes into account if the index is part of
     * data stream that's potentially managed by data stream lifecycle and the value of the
     * {@link org.elasticsearch.index.IndexSettings#PREFER_ILM_SETTING}
     */
    public boolean isIndexManagedByILM(IndexMetadata indexMetadata) {
        return project().isIndexManagedByILM(indexMetadata);
    }

    /**
     * Returns the full {@link ReservedStateMetadata} Map for all
     * reserved state namespaces.
     *
     * @return a map of namespace to {@link ReservedStateMetadata}
     */
    public Map<String, ReservedStateMetadata> reservedStateMetadata() {
        return this.reservedStateMetadata;
    }

    /**
     * The collection of index deletions in the cluster.
     */
    public IndexGraveyard indexGraveyard() {
        return project().indexGraveyard();
    }

    /**
     * Gets the total number of shards from all indices, including replicas and
     * closed indices for the current active project
     *
     * @return The total number shards from all indices (in the current active project)
     */
    public int getTotalNumberOfShards() {
        return project().getTotalNumberOfShards();
    }

    /**
     * Gets the total number of shards from all indices, including replicas and
     * closed indices across all projects
     *
     * @return The total number shards from all indices (in all projects)
     */
    public int getTotalNumberOfShardsInCluster() {
        return projects.values().stream().mapToInt(ProjectMetadata::getTotalNumberOfShards).sum();
    }

    /**
     * Gets the total number of open shards from all indices for the current active project.
     * Includes replicas, but does not include shards that are part of closed indices.
     *
     * @return The total number of open shards from all indices (in the current active project)
     */
    public int getTotalOpenIndexShards() {
        return project().getTotalOpenIndexShards();
    }

    /**
     * Gets the total number of open shards from all indices across all projects.
     * Includes replicas, but does not include shards that are part of closed indices.
     *
     * @return The total number of open shards from all indices (in all projects);
     */
    public int getTotalOpenIndexShardsInCluster() {
        return projects.values().stream().mapToInt(ProjectMetadata::getTotalOpenIndexShards).sum();
    }

    @Override
    public Iterator<IndexMetadata> iterator() {
        return project().iterator();
    }

    public Stream<IndexMetadata> stream() {
        return project().stream();
    }

    public int size() {
        return project().size();
    }

    public static boolean isGlobalStateEquals(Metadata metadata1, Metadata metadata2) {
        if (ClusterMetadata.isGlobalStateEquals(metadata1.clusterMetadata, metadata2.clusterMetadata) == false) {
            return false;
        }
        if (Objects.equals(metadata1.reservedStateMetadata, metadata2.reservedStateMetadata) == false) {
            return false;
        }
        if (metadata1.projects.size() != metadata2.projects.size()) {
            return false;
        }
        for (ProjectMetadata p1 : metadata1.projects()) {
            var p2 = metadata2.project(p1.id());
            if (p2 == null) {
                return false;
            }
            if (ProjectMetadata.isGlobalStateEquals(p1, p2) == false) {
                return false;
            }
        }
        return true;
    }

    @Override
    public Diff<Metadata> diff(Metadata previousState) {
        return new MetadataDiff(previousState, this);
    }

    public static Diff<Metadata> readDiffFrom(StreamInput in) throws IOException {
        if (in.getTransportVersion().onOrAfter(MetadataDiff.NOOP_METADATA_DIFF_VERSION) && in.readBoolean()) {
            return SimpleDiffable.empty();
        }
        return new MetadataDiff(in);
    }

    public static Metadata fromXContent(XContentParser parser) throws IOException {
        return Builder.fromXContent(parser);
    }

    @Override
    public Iterator<? extends ToXContent> toXContentChunked(ToXContent.Params p) {
        XContentContext context = XContentContext.from(p);
        final Iterator<? extends ToXContent> start = context == XContentContext.API
            ? ChunkedToXContentHelper.startObject("metadata")
            : Iterators.single((builder, params) -> builder.startObject("meta-data").field("version", version()));

        final Iterator<? extends ToXContent> projects = Iterators.flatMap(
            this.projects.values().iterator(),
            project -> ChunkedToXContentHelper.field(project.id().uuid(), project, p)
        );

        return Iterators.concat(
            start,
            clusterMetadata.toXContentChunked(p, context),
            ChunkedToXContentHelper.startObject("projects"),
            projects,
            ChunkedToXContentHelper.endObject(),
            ChunkedToXContentHelper.wrapWithObject("reserved_state", reservedStateMetadata().values().iterator()),
            ChunkedToXContentHelper.endObject()
        );
    }

    public Map<String, MappingMetadata> getMappingsByHash() {
        return project().getMappingsByHash();
    }

    private static class MetadataDiff implements Diff<Metadata> {

        private static final TransportVersion NOOP_METADATA_DIFF_VERSION = TransportVersions.V_8_5_0;
        private static final TransportVersion NOOP_METADATA_DIFF_SAFE_VERSION =
            PublicationTransportHandler.INCLUDES_LAST_COMMITTED_DATA_VERSION;

        private final long version;
        private final Diff<ClusterMetadata> cluster;
        private final Diff<Map<ProjectId, ProjectMetadata>> projects;
        private final Diff<Map<String, ReservedStateMetadata>> reservedStateMetadata;

        /**
         * true if this diff is a noop because before and after were the same instance
         */
        private final boolean empty;

        MetadataDiff(Metadata before, Metadata after) {
            this.empty = before == after;
            version = after.version;
            if (empty) {
                cluster = SimpleDiffable.empty();
                projects = DiffableUtils.emptyDiff();
                reservedStateMetadata = DiffableUtils.emptyDiff();
            } else {
                cluster = after.clusterMetadata.diff(before.clusterMetadata);
                projects = DiffableUtils.diff(before.projects, after.projects, ProjectId.KEY_SERIALIZER);
                reservedStateMetadata = DiffableUtils.diff(
                    before.reservedStateMetadata,
                    after.reservedStateMetadata,
                    DiffableUtils.getStringKeySerializer()
                );
            }
        }

        private static final DiffableUtils.DiffableValueReader<ProjectId, ProjectMetadata> PROJECT_DIFF_VALUE_READER =
            new DiffableUtils.DiffableValueReader<>(ProjectMetadata::readFrom, ProjectMetadata::readDiffFrom);

        private static final DiffableUtils.DiffableValueReader<String, ReservedStateMetadata> RESERVED_DIFF_VALUE_READER =
            new DiffableUtils.DiffableValueReader<>(ReservedStateMetadata::readFrom, ReservedStateMetadata::readDiffFrom);

        private MetadataDiff(StreamInput in) throws IOException {
            // @TODO[MultiProject] Add BWC reading
            empty = false;
            version = in.readLong();
            cluster = ClusterMetadata.readDiffFrom(in);
            projects = DiffableUtils.readJdkMapDiff(in, ProjectId.KEY_SERIALIZER, PROJECT_DIFF_VALUE_READER);
            reservedStateMetadata = DiffableUtils.readJdkMapDiff(in, DiffableUtils.getStringKeySerializer(), RESERVED_DIFF_VALUE_READER);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            // @TODO[MultiProject] Add BWC writing
            out.writeBoolean(empty);
            if (empty) {
                // noop diff
                return;
            }
            out.writeLong(version);
            cluster.writeTo(out);
            projects.writeTo(out);
            reservedStateMetadata.writeTo(out);
        }

        @Override
        public Metadata apply(Metadata part) {
            if (empty) {
                return part;
            }
            return new Metadata(
                part.version,
                this.cluster.apply(part.clusterMetadata),
                this.projects.apply(part.projects),
                this.reservedStateMetadata.apply(part.reservedStateMetadata)
            );
        }
    }

    public static Metadata readFrom(StreamInput in) throws IOException {
        // @TODO[MultiProject] BWC Reading
        var version = in.readLong();
        var cluster = ClusterMetadata.readFrom(in);
        var projects = in.readMapValues(ProjectMetadata::readFrom, ProjectMetadata::id);
        var rsm = in.readMapValues(ReservedStateMetadata::readFrom, ReservedStateMetadata::namespace);

        return new Metadata(version, cluster, projects, rsm);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        // @TODO[MultiProject] BWC Writing
        out.writeLong(version);
        clusterMetadata.writeTo(out);
        out.writeMapValues(projects);
        out.writeMapValues(reservedStateMetadata);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(Metadata metadata) {
        final Builder builder = new Builder(metadata);
        if (metadata.projects.isEmpty() == false) {
            builder.usingDefaultProject(metadata.currentProjectId());
        }
        return builder;
    }

    public Metadata copyAndUpdate(Consumer<Builder> updater) {
        var builder = builder(this);
        updater.accept(builder);
        return builder.build();
    }

    public static class Builder {

        private long version;

        private String clusterUUID;
        private boolean clusterUUIDCommitted;

        private CoordinationMetadata coordinationMetadata = CoordinationMetadata.EMPTY_METADATA;
        private Settings transientSettings = Settings.EMPTY;
        private Settings persistentSettings = Settings.EMPTY;
        private DiffableStringMap hashesOfConsistentSettings = DiffableStringMap.EMPTY;
        private final ImmutableOpenMap.Builder<String, ClusterMetadata.ClusterCustom> clusterCustoms;

        private final Map<ProjectId, ProjectMetadata.Builder> projects;

        private final Map<String, ReservedStateMetadata> reservedStateMetadata;
        private ProjectId defaultProject;

        public Builder() {
            this.version = 0;
            this.clusterUUID = UNKNOWN_CLUSTER_UUID;
            this.clusterCustoms = ImmutableOpenMap.builder();
            this.projects = new HashMap<>();
            this.reservedStateMetadata = new HashMap<>();
        }

        Builder(Metadata metadata) {
            this.version = metadata.version;
            this.clusterUUID = metadata.clusterMetadata.clusterUUID();
            this.clusterUUIDCommitted = metadata.clusterMetadata.clusterUUIDCommitted();
            this.coordinationMetadata = metadata.clusterMetadata.coordinationMetadata();
            this.transientSettings = metadata.clusterMetadata.transientSettings();
            this.persistentSettings = metadata.clusterMetadata.persistentSettings();
            this.hashesOfConsistentSettings = metadata.clusterMetadata.diffableHashesOfConsistentSettings();
            this.clusterCustoms = ImmutableOpenMap.builder(metadata.clusterMetadata.customs());
            this.projects = Maps.transformValues(metadata.projects, ProjectMetadata.Builder::new);
            this.reservedStateMetadata = new HashMap<>(metadata.reservedStateMetadata);
        }

        public ProjectMetadata.Builder project(ProjectId project) {
            Objects.requireNonNull(project);
            return this.projects.computeIfAbsent(project, ProjectMetadata.Builder::new);
        }

        public ProjectMetadata.Builder project() {
            return project(this.defaultProject());
        }

        private ProjectId defaultProject() {
            Objects.requireNonNull(this.defaultProject, "Default project has not been set");
            return defaultProject;
        }

        public Builder usingDefaultProject(ProjectId projectId) {
            this.defaultProject = projectId;
            return this;
        }

        public Builder createDefaultProject() {
            if (defaultProject == null) {
                final ProjectMetadata.Builder builder = ProjectMetadata.builder().id(this.clusterUUID);
                this.defaultProject = builder.id();
                return put(builder);
            } else {
                throw new IllegalStateException("A default project already exists");
            }
        }

        public Builder put(ProjectMetadata.Builder project) {
            var id = project.id();
            if (id == null) {
                throw new IllegalArgumentException("project id is null");
            }
            if (this.projects.containsKey(project.id())) {
                throw new IllegalStateException("Project [" + project.id() + "] already exists");
            }
            this.projects.put(project.id(), project);
            return this;
        }

        public Builder put(ProjectId project, IndexMetadata.Builder indexMetadataBuilder) {
            project(project).put(indexMetadataBuilder);
            return this;
        }

        public Builder put(IndexMetadata.Builder indexMetadataBuilder) {
            return put(defaultProject(), indexMetadataBuilder);
        }

        public Builder put(ProjectId projectId, IndexMetadata indexMetadata, boolean incrementVersion) {
            project(projectId).put(indexMetadata, incrementVersion);
            return this;
        }

        public Builder put(IndexMetadata indexMetadata, boolean incrementVersion) {
            return put(defaultProject(), indexMetadata, incrementVersion);
        }

        public IndexMetadata get(ProjectId projectId, String index) {
            return project(projectId).get(index);
        }

        public IndexMetadata get(String index) {
            return get(defaultProject(), index);
        }

        public IndexMetadata getSafe(ProjectId projectId, Index index) {
            return project(projectId).getSafe(index);
        }

        public IndexMetadata getSafe(Index index) {
            return getSafe(defaultProject(), index);
        }

        public Builder remove(ProjectId projectId, String index) {
            project(projectId).remove(index);
            return this;
        }

        public Builder remove(String index) {
            return remove(defaultProject(), index);
        }

        public Builder removeAllIndices(ProjectId projectId) {
            project(projectId).removeAllIndices();
            return this;
        }

        public Builder removeAllIndices() {
            return removeAllIndices(defaultProject());
        }

        public Builder indices(ProjectId projectId, Map<String, IndexMetadata> indices) {
            project(projectId).indices(indices);
            return this;
        }

        public Builder indices(Map<String, IndexMetadata> indices) {
            return this.indices(defaultProject(), indices);
        }

        public Builder put(ProjectId projectId, IndexTemplateMetadata.Builder template) {
            project(projectId).put(template.build());
            return this;
        }

        public Builder put(IndexTemplateMetadata.Builder template) {
            return put(defaultProject(), template);
        }

        public Builder put(ProjectId projectId, IndexTemplateMetadata template) {
            project(projectId).put(template);
            return this;
        }

        public Builder put(IndexTemplateMetadata template) {
            return put(defaultProject(), template);
        }

        public Builder removeTemplate(ProjectId projectId, String templateName) {
            project(projectId).removeTemplate(templateName);
            return this;
        }

        public Builder removeTemplate(String templateName) {
            return removeTemplate(defaultProject(), templateName);
        }

        public Builder templates(ProjectId projectId, Map<String, IndexTemplateMetadata> templates) {
            project(projectId).templates(templates);
            return this;
        }

        public Builder templates(Map<String, IndexTemplateMetadata> templates) {
            return templates(defaultProject(), templates);
        }

        public Builder put(ProjectId projectId, String name, ComponentTemplate componentTemplate) {
            project(projectId).put(name, componentTemplate);
            return this;
        }

        public Builder put(String name, ComponentTemplate componentTemplate) {
            return put(defaultProject(), name, componentTemplate);
        }

        public Builder removeComponentTemplate(ProjectId projectId, String name) {
            project(projectId).removeComponentTemplate(name);
            return this;
        }

        public Builder removeComponentTemplate(String name) {
            return removeComponentTemplate(defaultProject(), name);
        }

        public Builder componentTemplates(ProjectId projectId, Map<String, ComponentTemplate> componentTemplates) {
            project(projectId).componentTemplates(componentTemplates);
            return this;
        }

        public Builder componentTemplates(Map<String, ComponentTemplate> componentTemplates) {
            return componentTemplates(defaultProject(), componentTemplates);
        }

        public Builder indexTemplates(ProjectId projectId, Map<String, ComposableIndexTemplate> indexTemplates) {
            project(projectId).indexTemplates(indexTemplates);
            return this;
        }

        public Builder indexTemplates(Map<String, ComposableIndexTemplate> indexTemplates) {
            return indexTemplates(defaultProject(), indexTemplates);
        }

        public Builder put(ProjectId projectId, String name, ComposableIndexTemplate indexTemplate) {
            project(projectId).put(name, indexTemplate);
            return this;
        }

        public Builder put(String name, ComposableIndexTemplate indexTemplate) {
            return put(defaultProject(), name, indexTemplate);
        }

        public Builder removeIndexTemplate(ProjectId projectId, String name) {
            project(projectId).removeIndexTemplate(name);
            return this;
        }

        public Builder removeIndexTemplate(String name) {
            return removeIndexTemplate(defaultProject(), name);
        }

        public DataStream dataStream(ProjectId projectId, String dataStreamName) {
            return project(projectId).dataStream(dataStreamName);
        }

        public DataStream dataStream(String dataStreamName) {
            return dataStream(defaultProject(), dataStreamName);
        }

        public Builder dataStreams(
            ProjectId projectId,
            Map<String, DataStream> dataStreams,
            Map<String, DataStreamAlias> dataStreamAliases
        ) {
            project(projectId).dataStreams(dataStreams, dataStreamAliases);
            return this;
        }

        public Builder dataStreams(Map<String, DataStream> dataStreams, Map<String, DataStreamAlias> dataStreamAliases) {
            return dataStreams(defaultProject(), dataStreams, dataStreamAliases);
        }

        public Builder put(ProjectId projectId, DataStream dataStream) {
            project(projectId).put(dataStream);
            return this;
        }

        public Builder put(DataStream dataStream) {
            return put(defaultProject(), dataStream);
        }

        public DataStreamMetadata dataStreamMetadata(ProjectId projectId) {
            return project(projectId).dataStreamMetadata();
        }

        public boolean put(ProjectId projectId, String aliasName, String dataStream, Boolean isWriteDataStream, String filter) {
            return project(projectId).put(aliasName, dataStream, isWriteDataStream, filter);
        }

        public boolean put(String aliasName, String dataStream, Boolean isWriteDataStream, String filter) {
            return put(defaultProject(), aliasName, dataStream, isWriteDataStream, filter);
        }

        public Builder removeDataStream(ProjectId projectId, String name) {
            project(projectId).removeDataStream(name);
            return this;
        }

        public Builder removeDataStream(String name) {
            return removeDataStream(defaultProject(), name);
        }

        public boolean removeDataStreamAlias(ProjectId projectId, String aliasName, String dataStreamName, boolean mustExist) {
            return project(projectId).removeDataStreamAlias(aliasName, dataStreamName, mustExist);
        }

        public boolean removeDataStreamAlias(String aliasName, String dataStreamName, boolean mustExist) {
            return removeDataStreamAlias(defaultProject(), aliasName, dataStreamName, mustExist);
        }

        public ClusterMetadata.ClusterCustom getClusterCustom(String type) {
            return clusterCustoms.get(type);
        }

        public Builder putClusterCustom(String type, ClusterMetadata.ClusterCustom custom) {
            clusterCustoms.put(type, Objects.requireNonNull(custom, type));
            return this;
        }

        public Builder removeClusterCustom(String type) {
            clusterCustoms.remove(type);
            return this;
        }

        public Builder removeClusterCustomIf(BiPredicate<String, ClusterMetadata.ClusterCustom> p) {
            clusterCustoms.removeAll(p);
            return this;
        }

        public Builder clusterCustoms(Map<String, ClusterMetadata.ClusterCustom> customs) {
            customs.forEach((key, value) -> Objects.requireNonNull(value, key));
            this.clusterCustoms.putAllFromMap(customs);
            return this;
        }

        public ProjectMetadata.ProjectCustom getProjectCustom(ProjectId projectId, String type) {
            return project(projectId).getCustom(type);
        }

        public Builder putProjectCustom(ProjectId projectId, String type, ProjectMetadata.ProjectCustom custom) {
            project(projectId).putCustom(type, Objects.requireNonNull(custom, type));
            return this;
        }

        public Builder putProjectCustom(String type, ProjectMetadata.ProjectCustom custom) {
            return putProjectCustom(defaultProject(), type, custom);
        }

        public Builder removeProjectCustom(ProjectId projectId, String type) {
            project(projectId).removeCustom(type);
            return this;
        }

        public Builder removeProjectCustom(String type) {
            return removeProjectCustom(defaultProject(), type);
        }

        public Builder removeProjectCustomIf(ProjectId projectId, BiPredicate<String, ProjectMetadata.ProjectCustom> p) {
            project(projectId).removeCustomIf(p);
            return this;
        }

        public Builder projectCustoms(ProjectId projectId, Map<String, ProjectMetadata.ProjectCustom> customs) {
            project(projectId).customs(customs);
            return this;
        }

        /**
         * Adds a map of namespace to {@link ReservedStateMetadata} into the metadata builder
         *
         * @param reservedStateMetadata a map of namespace to {@link ReservedStateMetadata}
         * @return {@link Builder}
         */
        public Builder put(Map<String, ReservedStateMetadata> reservedStateMetadata) {
            this.reservedStateMetadata.putAll(reservedStateMetadata);
            return this;
        }

        /**
         * Adds a {@link ReservedStateMetadata} for a given namespace to the metadata builder
         *
         * @param metadata a {@link ReservedStateMetadata}
         * @return {@link Builder}
         */
        public Builder put(ReservedStateMetadata metadata) {
            reservedStateMetadata.put(metadata.namespace(), metadata);
            return this;
        }

        /**
         * Removes a {@link ReservedStateMetadata} for a given namespace
         *
         * @param metadata a {@link ReservedStateMetadata}
         * @return {@link Builder}
         */
        public Builder removeReservedState(ReservedStateMetadata metadata) {
            reservedStateMetadata.remove(metadata.namespace());
            return this;
        }

        public Builder indexGraveyard(ProjectId projectId, final IndexGraveyard indexGraveyard) {
            project(projectId).indexGraveyard(indexGraveyard);
            return this;
        }

        public Builder indexGraveyard(final IndexGraveyard indexGraveyard) {
            return this.indexGraveyard(defaultProject(), indexGraveyard);
        }

        public IndexGraveyard indexGraveyard(ProjectId projectId) {
            return project(projectId).indexGraveyard();
        }

        public IndexGraveyard indexGraveyard() {
            return indexGraveyard(defaultProject());
        }

        public Builder updateSettings(ProjectId projectId, Settings settings, String... indices) {
            project(projectId).updateSettings(settings, indices);
            return this;
        }

        public Builder updateSettings(Settings settings, String... indices) {
            return updateSettings(defaultProject(), settings, indices);
        }

        /**
         * Update the number of replicas for the specified indices.
         *
         * @param numberOfReplicas the number of replicas
         * @param indices          the indices to update the number of replicas for
         * @return the builder
         */
        public Builder updateNumberOfReplicas(ProjectId projectId, final int numberOfReplicas, final String[] indices) {
            project(projectId).updateNumberOfReplicas(numberOfReplicas, indices);
            return this;
        }

        public Builder updateNumberOfReplicas(final int numberOfReplicas, final String[] indices) {
            return updateNumberOfReplicas(defaultProject(), numberOfReplicas, indices);
        }

        public Builder coordinationMetadata(CoordinationMetadata coordinationMetadata) {
            this.coordinationMetadata = coordinationMetadata;
            return this;
        }

        public Settings transientSettings() {
            return this.transientSettings;
        }

        public Builder transientSettings(Settings settings) {
            this.transientSettings = settings;
            return this;
        }

        public Settings persistentSettings() {
            return this.persistentSettings;
        }

        public Builder persistentSettings(Settings settings) {
            this.persistentSettings = settings;
            return this;
        }

        public Builder hashesOfConsistentSettings(DiffableStringMap hashesOfConsistentSettings) {
            this.hashesOfConsistentSettings = hashesOfConsistentSettings;
            return this;
        }

        public Builder hashesOfConsistentSettings(Map<String, String> hashesOfConsistentSettings) {
            this.hashesOfConsistentSettings = new DiffableStringMap(hashesOfConsistentSettings);
            return this;
        }

        public Builder version(long version) {
            this.version = version;
            return this;
        }

        public Builder clusterUUID(String clusterUUID) {
            this.clusterUUID = clusterUUID;
            return this;
        }

        public Builder clusterUUIDCommitted(boolean clusterUUIDCommitted) {
            this.clusterUUIDCommitted = clusterUUIDCommitted;
            return this;
        }

        public Builder generateClusterUuidIfNeeded() {
            if (clusterUUID.equals(UNKNOWN_CLUSTER_UUID)) {
                clusterUUID = UUIDs.randomBase64UUID();
            }
            return this;
        }

        /**
         * @return a new <code>Metadata</code> instance
         */
        public Metadata build() {
            return build(false);
        }

        public Metadata build(boolean skipNameCollisionChecks) {
            return new Metadata(
                version,
                new ClusterMetadata(
                    clusterUUID,
                    clusterUUIDCommitted,
                    coordinationMetadata,
                    transientSettings,
                    persistentSettings,
                    hashesOfConsistentSettings,
                    clusterCustoms.build()
                ),
                Maps.transformValues(projects, builder -> builder.build(skipNameCollisionChecks)),
                Collections.unmodifiableMap(reservedStateMetadata)
            );
        }

        public static Metadata fromXContent(XContentParser parser) throws IOException {
            Builder builder = new Builder();

            // we might get here after the meta-data element, or on a fresh parser
            XContentParser.Token token = parser.currentToken();
            String currentFieldName = parser.currentName();
            if ("meta-data".equals(currentFieldName) == false) {
                token = parser.nextToken();
                if (token == XContentParser.Token.START_OBJECT) {
                    // move to the field name (meta-data)
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser);
                    // move to the next object
                    token = parser.nextToken();
                }
                currentFieldName = parser.currentName();
            }

            if ("meta-data".equals(currentFieldName) == false) {
                throw new IllegalArgumentException("Expected [meta-data] as a field name but got " + currentFieldName);
            }
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, token, parser);

            while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                if (token == XContentParser.Token.FIELD_NAME) {
                    currentFieldName = parser.currentName();
                } else if (token == XContentParser.Token.START_OBJECT) {
                    if ("cluster_coordination".equals(currentFieldName)) {
                        builder.coordinationMetadata(CoordinationMetadata.fromXContent(parser));
                    } else if ("settings".equals(currentFieldName)) {
                        builder.persistentSettings(Settings.fromXContent(parser));
                    } else if ("reserved_state".equals(currentFieldName)) {
                        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                            builder.put(ReservedStateMetadata.fromXContent(parser));
                        }
                    } else if ("projects".equals(currentFieldName)) {
                        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                            if (token == XContentParser.Token.FIELD_NAME) {
                                // Skip project id
                            } else if (token == XContentParser.Token.START_OBJECT) {
                                builder.put(ProjectMetadata.Builder.fromXContent(parser));
                            } else {
                                throw new IllegalArgumentException("Unexpected token " + token);
                            }
                        }
                    } else {
                        try {
                            var custom = parser.namedObject(ClusterMetadata.ClusterCustom.class, currentFieldName, null);
                            builder.putClusterCustom(custom.getWriteableName(), custom);
                        } catch (NamedObjectNotFoundException ex) {
                            logger.warn("Skipping unknown custom object with type {}", currentFieldName);
                            parser.skipChildren();
                        }
                    }
                } else if (token.isValue()) {
                    if ("version".equals(currentFieldName)) {
                        builder.version = parser.longValue();
                    } else if ("cluster_uuid".equals(currentFieldName) || "uuid".equals(currentFieldName)) {
                        builder.clusterUUID = parser.text();
                    } else if ("cluster_uuid_committed".equals(currentFieldName)) {
                        builder.clusterUUIDCommitted = parser.booleanValue();
                    } else {
                        throw new IllegalArgumentException("Unexpected field [" + currentFieldName + "]");
                    }
                } else {
                    throw new IllegalArgumentException("Unexpected token " + token);
                }
            }
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser);
            return builder.build();
        }
    }

    private static final ToXContent.Params FORMAT_PARAMS;

    static {
        Map<String, String> params = Maps.newMapWithExpectedSize(2);
        params.put("binary", "true");
        params.put(Metadata.CONTEXT_MODE_PARAM, Metadata.CONTEXT_MODE_GATEWAY);
        FORMAT_PARAMS = new ToXContent.MapParams(params);
    }

    /**
     * State format for {@link Metadata} to write to and load from disk
     */
    public static final MetadataStateFormat<Metadata> FORMAT = new MetadataStateFormat<>(GLOBAL_STATE_FILE_PREFIX) {

        @Override
        public void toXContent(XContentBuilder builder, Metadata state) throws IOException {
            ChunkedToXContent.wrapAsToXContent(state).toXContent(builder, FORMAT_PARAMS);
        }

        @Override
        public Metadata fromXContent(XContentParser parser) throws IOException {
            return Builder.fromXContent(parser);
        }
    };
}
