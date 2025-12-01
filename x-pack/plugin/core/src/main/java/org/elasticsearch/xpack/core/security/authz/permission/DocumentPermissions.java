/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.join.BitSetProducer;
import org.apache.lucene.search.join.ToChildBlockJoinQuery;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.lucene.search.Queries;
import org.elasticsearch.core.CheckedFunction;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.index.mapper.NestedLookup;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryRewriteContext;
import org.elasticsearch.index.query.Rewriteable;
import org.elasticsearch.index.query.SearchExecutionContext;
import org.elasticsearch.index.search.NestedHelper;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.security.authz.support.DLSRoleQueryValidator;
import org.elasticsearch.xpack.core.security.support.CacheKey;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.apache.lucene.search.BooleanClause.Occur.FILTER;
import static org.apache.lucene.search.BooleanClause.Occur.SHOULD;

/**
 * Stores document level permissions in the form queries that match all the accessible documents.<br>
 * The document level permissions may be limited by another set of queries in that case the limited
 * queries are used as an additional filter.
 */
public final class DocumentPermissions implements CacheKey {

    /**
     * The outer collection represents the intersection of roles (see {@link LimitedRole}).
     * The inner collection represents the union of queries across assigned roles/index permissions.
     * <br />
     * A document is viewable if it matches at least one inner query in each of the outer groups.
     * That is
     * <pre>
     *   boolean visible = queries.stream().allMatch(
     *     inner -> inner.stream().anyMatch(
     *       query -> evaluate(query, user)
     *     )
     *   );
     * </pre>
     */
    public record DocumentQueries<T>(List<Collection<T>> queries) {
        public Collection<T> singletonInner() {
            assert queries != null && queries.size() == 1 : "the list of queries does not have a single member";
            return queries.getFirst();
        }

        public <E extends Exception> boolean anyMatch(CheckedFunction<T, Boolean, E> predicate) throws E {
            for (var inner : queries) {
                for (T query : inner) {
                    if (predicate.apply(query)) {
                        return true;
                    }
                }
            }
            return false;
        }

        public Stream<Collection<T>> outer() {
            return queries.stream();
        }

        public boolean isEmpty() {
            return queries.isEmpty();
        }

        public int outerSize() {
            return queries.size();
        }

        public Collection<T> getInner(int index) {
            return queries.get(index);
        }

        public DocumentQueries<T> concat(DocumentQueries<T> other) {
            return new DocumentQueries<>(Stream.concat(this.queries.stream(), other.queries.stream()).toList());
        }

        public <S> DocumentQueries<S> map(Function<T, S> func) {
            return new DocumentQueries<>((this.queries.stream().map(inner -> (Collection<S>) inner.stream().map(func).toList())).toList());
        }

        public void writeTo(StreamOutput out, final Writeable.Writer<Collection<T>> writer) throws IOException {
            out.writeCollection(queries, writer);
        }
    }

    @Nullable
    private final DocumentQueries<DocumentSecurityQuery> assignedQueries;
    @Nullable
    private DocumentQueries<String> listOfEvaluatedQueries;

    private static final DocumentPermissions ALLOW_ALL = new DocumentPermissions();

    private DocumentPermissions() {
        this.assignedQueries = null;
    }

    public DocumentPermissions(DocumentQueries<DocumentSecurityQuery> queries) {
        assert queries != null && false == queries.isEmpty() : "null or empty queries not permitted";
        this.assignedQueries = queries;
    }

    private DocumentPermissions(Set<DocumentSecurityQuery> queries) {
        assert queries != null && false == queries.isEmpty() : "null or empty queries not permitted";
        this.assignedQueries = new DocumentQueries<>(List.of(new TreeSet<>(queries)));
    }

    private DocumentPermissions(List<Set<DocumentSecurityQuery>> assignedQueries) {
        assert assignedQueries != null && false == assignedQueries.isEmpty() : "null or empty list of queries not permitted";
        assert assignedQueries.stream().allMatch(queries -> queries != null && false == queries.isEmpty())
            : "null or empty queries not permitted";
        // SortedSet because orders are important when they get serialised for request cache key
        this.assignedQueries = new DocumentQueries<>(
            assignedQueries.stream()
                .map(
                    queries -> (Collection<DocumentSecurityQuery>) (queries instanceof SortedSet<DocumentSecurityQuery>
                        ? queries
                        : new TreeSet<>(queries))
                )
                .toList()
        );
    }

    public DocumentQueries<DocumentSecurityQuery> getAssignedQueries() {
        return assignedQueries;
    }

    public Collection<DocumentSecurityQuery> getSingleSetOfQueries() {
        assert assignedQueries != null;
        return assignedQueries.singletonInner();
    }

    /**
     * @return {@code true} if either queries or scoped queries are present for document level security else returns {@code false}
     */
    public boolean hasDocumentLevelPermissions() {
        return assignedQueries != null;
    }

    public boolean hasStoredScript() throws IOException {
        if (assignedQueries != null) {
            return assignedQueries.anyMatch(q -> DLSRoleQueryValidator.hasStoredScript(q, NamedXContentRegistry.EMPTY));
        }
        return false;
    }

    /**
     * Creates a {@link BooleanQuery} to be used as filter to restrict access to documents.<br>
     * Document permission queries are used to create a boolean query.<br>
     * If the document permissions are limited, then there is an additional filter added restricting access to documents only allowed by the
     * limited queries.
     *
     * @param shardId {@link ShardId}
     * @param searchExecutionContextProvider {@link SearchExecutionContext}
     * @return {@link BooleanQuery} for the filter
     * @throws IOException thrown if there is an exception during parsing
     */
    public BooleanQuery filter(ShardId shardId, Function<ShardId, SearchExecutionContext> searchExecutionContextProvider)
        throws IOException {
        if (hasDocumentLevelPermissions()) {
            evaluateQueries();
            assert listOfEvaluatedQueries != null : "evaluated queries must not be null";
            assert false == listOfEvaluatedQueries.isEmpty() : "evaluated queries must not be empty";

            BooleanQuery.Builder filter = new BooleanQuery.Builder();
            for (int i = listOfEvaluatedQueries.outerSize() - 1; i > 0; i--) {
                final BooleanQuery.Builder scopedFilter = new BooleanQuery.Builder();
                buildRoleQuery(shardId, searchExecutionContextProvider, listOfEvaluatedQueries.getInner(i), scopedFilter);
                filter.add(scopedFilter.build(), FILTER);
            }
            // TODO: All role queries can be filters
            buildRoleQuery(shardId, searchExecutionContextProvider, listOfEvaluatedQueries.getInner(0), filter);
            return filter.build();
        }
        return null;
    }

    private DocumentQueries<String> evaluateQueries() throws IOException {
        if (assignedQueries != null && listOfEvaluatedQueries == null) {
            listOfEvaluatedQueries = assignedQueries.map(DocumentSecurityQuery::getQueryDsl);
        }
        return listOfEvaluatedQueries;
    }

    private static void buildRoleQuery(
        ShardId shardId,
        Function<ShardId, SearchExecutionContext> searchExecutionContextProvider,
        Collection<String> queries,
        BooleanQuery.Builder filter
    ) throws IOException {
        for (String query : queries) {
            SearchExecutionContext context = searchExecutionContextProvider.apply(shardId);
            QueryBuilder queryBuilder = DLSRoleQueryValidator.parseAndVerifyRoleQuery(query, context.getParserConfig().registry());
            if (queryBuilder != null) {
                failIfQueryUsesClient(queryBuilder, context);
                Query roleQuery = context.toQuery(queryBuilder).query();
                if (context.nestedLookup() == NestedLookup.EMPTY) {
                    filter.add(roleQuery, SHOULD);
                } else {
                    if (NestedHelper.mightMatchNestedDocs(roleQuery, context)) {
                        roleQuery = new BooleanQuery.Builder().add(roleQuery, FILTER)
                            .add(Queries.newNonNestedFilter(context.indexVersionCreated()), FILTER)
                            .build();
                    }
                    filter.add(roleQuery, SHOULD);
                    // If access is allowed on root doc then also access is allowed on all nested docs of that root document:
                    BitSetProducer rootDocs = context.bitsetFilter(Queries.newNonNestedFilter(context.indexVersionCreated()));
                    ToChildBlockJoinQuery includeNestedDocs = new ToChildBlockJoinQuery(roleQuery, rootDocs);
                    filter.add(includeNestedDocs, SHOULD);
                }
            }
        }
        // at least one of the queries should match
        filter.setMinimumNumberShouldMatch(1);
    }

    /**
     * Fall back validation that verifies that queries during rewrite don't use
     * the client to make remote calls. In the case of DLS this can cause a dead
     * lock if DLS is also applied on these remote calls. For example in the
     * case of terms query with lookup, this can cause recursive execution of
     * the DLS query until the get thread pool has been exhausted:
     * https://github.com/elastic/x-plugins/issues/3145
     */
    static void failIfQueryUsesClient(QueryBuilder queryBuilder, QueryRewriteContext original) throws IOException {
        QueryRewriteContext copy = new QueryRewriteContext(original.getParserConfig(), null, original::nowInMillis);
        Rewriteable.rewrite(queryBuilder, copy);
        if (copy.hasAsyncActions()) {
            throw new IllegalStateException("role queries are not allowed to execute additional requests");
        }
    }

    /**
     * Create {@link DocumentPermissions} for given set of queries
     * @param queries set of queries
     * @return {@link DocumentPermissions}
     */
    public static DocumentPermissions filteredBy(Set<DocumentSecurityQuery> queries) {
        return new DocumentPermissions(queries);
    }

    public static DocumentPermissions allowAll() {
        return ALLOW_ALL;
    }

    /**
     * Create a document permissions, where the permissions for {@code this} are
     * limited by the queries from other document permissions.<br>
     *
     * @param limitedByDocumentPermissions {@link DocumentPermissions} used to limit the document level access
     * @return instance of {@link DocumentPermissions}
     */
    public DocumentPermissions limitDocumentPermissions(DocumentPermissions limitedByDocumentPermissions) {
        if (hasDocumentLevelPermissions() && limitedByDocumentPermissions.hasDocumentLevelPermissions()) {
            assert limitedByDocumentPermissions.assignedQueries != null;
            return new DocumentPermissions(this.assignedQueries.concat(limitedByDocumentPermissions.assignedQueries));
        } else if (hasDocumentLevelPermissions()) {
            return new DocumentPermissions(this.getAssignedQueries());
        } else if (limitedByDocumentPermissions.hasDocumentLevelPermissions()) {
            return new DocumentPermissions(limitedByDocumentPermissions.getAssignedQueries());
        } else {
            return DocumentPermissions.allowAll();
        }
    }

    @Override
    public String toString() {
        return "DocumentPermissions [listOfQueries=" + assignedQueries + "]";
    }

    @Override
    public void buildCacheKey(StreamOutput out) throws IOException {
        assert hasDocumentLevelPermissions() : "document permissions should not contribute to cache key when there is no DLS query";
        evaluateQueries().writeTo(out, StreamOutput::writeStringCollection);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DocumentPermissions that = (DocumentPermissions) o;
        return Objects.equals(assignedQueries, that.assignedQueries);
    }

    @Override
    public int hashCode() {
        return Objects.hash(assignedQueries);
    }
}
