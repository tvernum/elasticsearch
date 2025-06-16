/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.action.role;

import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.TransportAction;
import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.action.support.nodes.BaseNodesRequest;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.action.support.nodes.BaseNodesXContentResponse;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ChunkedToXContentHelper;
import org.elasticsearch.injection.guice.Inject;
import org.elasticsearch.persistent.PersistentTaskResponse;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.AbstractTransportRequest;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xcontent.ToXContent;
import org.elasticsearch.xcontent.ToXContentFragment;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xpack.core.security.action.ClearSecurityCacheResponse;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.DocumentSubsetBitsetCache;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

public class GetDlsStatsAction {

    public static final ActionType<Response> TYPE = new ActionType<>("cluster:admin/xpack/security/role/dls/stats");

    public static class Request extends BaseNodesRequest {
        public Request() {
            super(new String[0]);
        }
    }

    public static class Stats extends BaseNodeResponse implements ToXContentObject {

        private final Map<String, Object> stats;

        public Stats(DiscoveryNode node, Map<String, Object> stats) {
            super(node);
            this.stats = stats;
        }

        public Stats(StreamInput in) throws IOException {
            super(in);
            stats = in.readMap(StreamInput::readGenericValue);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("name", getNode().getName());
            builder.field("stats", stats);
            return builder.endObject();
        }
    }

    public static class Response extends BaseNodesResponse<Stats> implements ToXContentObject {

        public Response(ClusterName clusterName, List<Stats> nodes, List<FailedNodeException> failures) {
            super(clusterName, nodes, failures);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.startObject("nodes");
            for (var node : getNodes()) {
                builder.field(node.getNode().getId(), node);
            }
            builder.endObject();
            builder.endObject();
            return builder;
        }

        @Override
        protected List<Stats> readNodesFrom(StreamInput in) throws IOException {
            return TransportAction.localOnly();
        }

        @Override
        protected void writeNodesTo(StreamOutput out, List<Stats> nodes) throws IOException {
            TransportAction.localOnly();
        }
    }

    public static final class InnerRequest extends AbstractTransportRequest {
        public InnerRequest(StreamInput in) throws IOException {
            super(in);
        }

        public InnerRequest() {}
    }

    public static class StatsTransportAction extends TransportNodesAction<Request, Response, InnerRequest, Stats, Object> {

        private final DocumentSubsetBitsetCache dlsCache;

        @Inject
        public StatsTransportAction(
            ThreadPool threadPool,
            ClusterService clusterService,
            TransportService transportService,
            ActionFilters actionFilters,
            CompositeRolesStore rolesStore
        ) {
            super(
                TYPE.name(),
                clusterService,
                transportService,
                actionFilters,
                InnerRequest::new,
                threadPool.executor(ThreadPool.Names.MANAGEMENT)
            );
            this.dlsCache = rolesStore.getDlsBitsetCache();
        }

        @Override
        protected Response newResponse(Request request, List<Stats> stats, List<FailedNodeException> failures) {
            return new Response(clusterService.getClusterName(), stats, failures);
        }

        @Override
        protected InnerRequest newNodeRequest(Request request) {
            return new InnerRequest();
        }

        @Override
        protected Stats newNodeResponse(StreamInput in, DiscoveryNode node) throws IOException {
            return new Stats(in);
        }

        @Override
        protected Stats nodeOperation(InnerRequest request, Task task) {
            return new Stats(transportService.getLocalNode(), dlsCache.usageStats());
        }
    }
}
