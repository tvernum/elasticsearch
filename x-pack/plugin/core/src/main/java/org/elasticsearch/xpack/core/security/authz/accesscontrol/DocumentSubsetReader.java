/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.security.authz.accesscontrol;

import org.apache.lucene.codecs.StoredFieldsReader;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.PostingsEnum;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.Query;
import org.apache.lucene.store.AlreadyClosedException;
import org.apache.lucene.util.BitSet;
import org.apache.lucene.util.BitSetIterator;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.UnwrapForGlobalOrdsFilterDirectoryReader;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.common.cache.Cache;
import org.elasticsearch.common.cache.CacheBuilder;
import org.elasticsearch.common.logging.LoggerMessageFormat;
import org.elasticsearch.common.lucene.index.SequentialStoredFieldsLeafReader;
import org.elasticsearch.lucene.util.CombinedBitSet;
import org.elasticsearch.lucene.util.MatchAllBitSet;
import org.elasticsearch.transport.Transports;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

/**
 * A reader that only exposes documents via {@link #getLiveDocs()} that matches with the provided role query.
 */
public final class DocumentSubsetReader extends SequentialStoredFieldsLeafReader {

    public static DocumentSubsetDirectoryReader wrap(
        DirectoryReader in,
        DocumentSubsetBitsetCache bitsetCache,
        Query roleQuery,
        boolean strictTermsEnum
    ) throws IOException {
        return new DocumentSubsetDirectoryReader(in, bitsetCache, roleQuery, strictTermsEnum);
    }

    /**
     * Cache of the number of live docs for a given (segment, role query) pair.
     * This is useful because numDocs() is called eagerly by BaseCompositeReader so computing
     * numDocs() lazily doesn't help. Plus it helps reuse the result of the computation either
     * between refreshes, or across refreshes if no more documents were deleted in the
     * considered segment. The size of the top-level map is bounded by the number of segments
     * on the node.
     */
    static final Map<IndexReader.CacheKey, Cache<Query, Integer>> NUM_DOCS_CACHE = new ConcurrentHashMap<>();

    /**
     * Compute the number of live documents. This method is SLOW.
     */
    private static int computeNumDocs(LeafReader reader, BitSet roleQueryBits) {
        final Bits liveDocs = reader.getLiveDocs();
        if (roleQueryBits == null) {
            return 0;
        } else if (roleQueryBits instanceof MatchAllBitSet) {
            return reader.numDocs();
        } else if (liveDocs == null) {
            // slow
            return roleQueryBits.cardinality();
        } else {
            // very slow, but necessary in order to be correct
            int numDocs = 0;
            DocIdSetIterator it = new BitSetIterator(roleQueryBits, 0L); // we don't use the cost
            try {
                for (int doc = it.nextDoc(); doc != DocIdSetIterator.NO_MORE_DOCS; doc = it.nextDoc()) {
                    if (liveDocs.get(doc)) {
                        numDocs++;
                    }
                }
                return numDocs;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    /**
     * Like {@link #computeNumDocs} but caches results.
     */
    private static int getNumDocs(LeafReader reader, Query roleQuery, BitSet roleQueryBits) throws IOException, ExecutionException {
        IndexReader.CacheHelper cacheHelper = reader.getReaderCacheHelper(); // this one takes deletes into account
        if (cacheHelper == null) {
            return computeNumDocs(reader, roleQueryBits);
        }
        final boolean[] added = new boolean[] { false };
        Cache<Query, Integer> perReaderCache = NUM_DOCS_CACHE.computeIfAbsent(cacheHelper.getKey(), key -> {
            added[0] = true;
            return CacheBuilder.<Query, Integer>builder()
                // Not configurable, this limit only exists so that if a role query is updated
                // then we won't risk OOME because of old role queries that are not used anymore
                .setMaximumWeight(1000)
                .weigher((k, v) -> 1) // just count
                .build();
        });
        if (added[0]) {
            IndexReader.ClosedListener closedListener = NUM_DOCS_CACHE::remove;
            try {
                cacheHelper.addClosedListener(closedListener);
            } catch (AlreadyClosedException e) {
                closedListener.onClose(cacheHelper.getKey());
                throw e;
            }
        }
        return perReaderCache.computeIfAbsent(roleQuery, q -> computeNumDocs(reader, roleQueryBits));
    }

    public static final class DocumentSubsetDirectoryReader extends UnwrapForGlobalOrdsFilterDirectoryReader {

        private final Query roleQuery;
        private final DocumentSubsetBitsetCache bitsetCache;
        private boolean strictTermsEnum;

        DocumentSubsetDirectoryReader(
            final DirectoryReader in,
            final DocumentSubsetBitsetCache bitsetCache,
            final Query roleQuery,
            boolean strictTermsEnum
        ) throws IOException {
            super(in, new SubReaderWrapper() {
                @Override
                public LeafReader wrap(LeafReader reader) {
                    try {
                        return new DocumentSubsetReader(reader, bitsetCache, roleQuery, strictTermsEnum);
                    } catch (Exception e) {
                        throw ExceptionsHelper.convertToElastic(e);
                    }
                }
            });
            this.bitsetCache = bitsetCache;
            this.roleQuery = roleQuery;
            this.strictTermsEnum = strictTermsEnum;

            verifyNoOtherDocumentSubsetDirectoryReaderIsWrapped(in);
        }

        @Override
        protected DirectoryReader doWrapDirectoryReader(DirectoryReader in) throws IOException {
            return new DocumentSubsetDirectoryReader(in, bitsetCache, roleQuery, strictTermsEnum);
        }

        private static void verifyNoOtherDocumentSubsetDirectoryReaderIsWrapped(DirectoryReader reader) {
            if (reader instanceof FilterDirectoryReader filterDirectoryReader) {
                if (filterDirectoryReader instanceof DocumentSubsetDirectoryReader) {
                    throw new IllegalArgumentException(
                        LoggerMessageFormat.format("Can't wrap [{}] twice", DocumentSubsetDirectoryReader.class)
                    );
                } else {
                    verifyNoOtherDocumentSubsetDirectoryReaderIsWrapped(filterDirectoryReader.getDelegate());
                }
            }
        }

        @Override
        public CacheHelper getReaderCacheHelper() {
            return in.getReaderCacheHelper();
        }
    }

    private final DocumentSubsetBitsetCache bitsetCache;
    private final Query roleQuery;
    private final boolean strictTermsEnum;

    // we don't use a volatile here because the bitset is resolved before numDocs in the synchronized block
    // so any thread that see numDocs != -1 should also see the true value of the roleQueryBits (happens-before).
    private BitSet roleQueryBits;
    private volatile int numDocs = -1;

    private DocumentSubsetReader(
        final LeafReader in,
        DocumentSubsetBitsetCache bitsetCache,
        final Query roleQuery,
        final boolean strictTermsEnum
    ) throws Exception {
        super(in);
        this.bitsetCache = bitsetCache;
        this.roleQuery = roleQuery;
        this.strictTermsEnum = strictTermsEnum;
    }

    /**
     * Resolve the role query and the number of docs lazily
     */
    private void computeNumDocsIfNeeded() {
        if (numDocs == -1) {
            synchronized (this) {
                if (numDocs == -1) {
                    assert Transports.assertNotTransportThread("resolving role query");
                    try {
                        roleQueryBits = bitsetCache.getBitSet(roleQuery, in.getContext());
                        numDocs = getNumDocs(in, roleQuery, roleQueryBits);
                    } catch (Exception e) {
                        throw new ElasticsearchException("Failed to load role query", e);
                    }
                }
            }
        }
    }

    @Override
    public Bits getLiveDocs() {
        computeNumDocsIfNeeded();
        final Bits actualLiveDocs = in.getLiveDocs();
        if (roleQueryBits == null) {
            // If we would return a <code>null</code> liveDocs then that would mean that no docs are marked as deleted,
            // but that isn't the case. No docs match with the role query and therefore all docs are marked as deleted
            return new Bits.MatchNoBits(in.maxDoc());
        } else if (roleQueryBits instanceof MatchAllBitSet) {
            return actualLiveDocs;
        } else if (actualLiveDocs == null) {
            return roleQueryBits;
        } else {
            // apply deletes when needed:
            return new CombinedBitSet(roleQueryBits, actualLiveDocs);
        }
    }

    @Override
    public int numDocs() {
        computeNumDocsIfNeeded();
        return numDocs;
    }

    @Override
    public boolean hasDeletions() {
        // we always return liveDocs and hide docs:
        return true;
    }

    @Override
    public CacheHelper getCoreCacheHelper() {
        return in.getCoreCacheHelper();
    }

    @Override
    public CacheHelper getReaderCacheHelper() {
        // Not delegated since we change the live docs
        return null;
    }

    @Override
    protected StoredFieldsReader doGetSequentialStoredFieldsReader(StoredFieldsReader reader) {
        return reader;
    }

    BitSet getRoleQueryBits() {
        return roleQueryBits;
    }

    Bits getWrappedLiveDocs() {
        return in.getLiveDocs();
    }

    @Override
    public Terms terms(String field) throws IOException {
        Terms t = super.terms(field);
        if (strictTermsEnum == false || null == t) {
            return t;
        } else {
            return new DocumentSafeTerms(t);
        }
    }

    @Override
    public SortedDocValues getSortedDocValues(String field) throws IOException {
        final SortedDocValues sortedDocValues = in.getSortedDocValues(field);
        if (strictTermsEnum == false) {
            return sortedDocValues;
        } else {
            final Bits liveDocs = getLiveDocs();
            final TermsEnum invertedIndexTermsEnum = getInvertedIndexTermsEnum(field);
            return new DocumentSafeSortedDocValues(sortedDocValues, invertedIndexTermsEnum, liveDocs);
        }
    }

    @Override
    public SortedSetDocValues getSortedSetDocValues(String field) throws IOException {
        final SortedSetDocValues sortedSetDocValues = in.getSortedSetDocValues(field);
        if (strictTermsEnum == false) {
            return sortedSetDocValues;
        } else {
            final Bits liveDocs = getLiveDocs();
            final TermsEnum invertedIndexTermsEnum = getInvertedIndexTermsEnum(field);
            return new DocumentSafeSortedSetDocValues(sortedSetDocValues, invertedIndexTermsEnum, liveDocs);
        }
    }

    private TermsEnum getInvertedIndexTermsEnum(String field) throws IOException {
        final Terms terms = in.terms(field);
        final TermsEnum invertedIndexTermsEnum;
        if (terms == null) {
            invertedIndexTermsEnum = null;
        } else {
            invertedIndexTermsEnum = terms.iterator();
        }
        return invertedIndexTermsEnum;
    }

    static class DocumentSafeTerms extends FilterTerms {

        DocumentSafeTerms(Terms in) {
            super(in);
        }

        @Override
        public TermsEnum iterator() throws IOException {
            return new DocumentSafeTermsEnum(in.iterator());
        }
    }

    static class DocumentSafeTermsEnum extends FilterTermsEnum {

        DocumentSafeTermsEnum(TermsEnum in) {
            super(in);
        }

        @Override
        public SeekStatus seekCeil(BytesRef term) {
            throw new UnsupportedOperationException(
                "This query type is disallowed when "
                    + IndexMetadata.INDEX_PRIORITY_SETTING.getKey()
                    + " is set to true, as it can inadvertently leak terms that DLS would not permit."
            );
        }

        @Override
        public BytesRef next() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void seekExact(long ord) throws IOException {
            throw new UnsupportedOperationException(
                "This query type is disallowed when "
                    + IndexMetadata.INDEX_PRIORITY_SETTING.getKey()
                    + " is set to true, as it can inadvertently leak terms that DLS would not permit."
            );
        }
    }

    /**
     * A {@link TermsEnum} for doc-values that cross-checks lookups by ord with
     * the terms dictionary of the inverted index to prevent lookup by ord on
     * terms that are only contained by deleted documents.
     */
    static class DocumentSafeDocValuesTermsEnum extends DocumentSafeTermsEnum {

        private final TermsEnum invertedIndexTermsEnum;
        private final Bits liveDocs;
        private PostingsEnum postings;

        DocumentSafeDocValuesTermsEnum(TermsEnum in, TermsEnum invertedIndexTermsEnum, Bits liveDocs) {
            super(in);
            this.liveDocs = liveDocs;
            this.invertedIndexTermsEnum = Objects.requireNonNull(invertedIndexTermsEnum);
        }

        @Override
        public void seekExact(long ord) throws IOException {
            in.seekExact(ord);
            // invertedIndexTermsEnum usually doesn't support lookup by ord
            // so we are looking up by term
            BytesRef term = in.term();
            boolean termIsLive = false;
            if (invertedIndexTermsEnum.seekExact(term)) {
                postings = invertedIndexTermsEnum.postings(postings, PostingsEnum.NONE);
                for (int doc = postings.nextDoc(); doc != DocIdSetIterator.NO_MORE_DOCS; doc = postings.nextDoc()) {
                    if (liveDocs == null || liveDocs.get(doc)) {
                        termIsLive = true;
                        break;
                    }
                }
            }
            if (termIsLive == false) {
                throw new UnsupportedOperationException("Lookup by ord on random ords is disallowed");
            }
        }

    }

    static class DocumentSafeSortedDocValues extends SortedDocValues {

        private final SortedDocValues in;
        private final TermsEnum invertedIndexTermsEnum;
        private final Bits liveDocs;
        private final TermsEnum termsEnum;

        DocumentSafeSortedDocValues(SortedDocValues in, TermsEnum invertedIndexTermsEnum, Bits liveDocs) throws IOException {
            this.in = in;
            this.invertedIndexTermsEnum = invertedIndexTermsEnum;
            this.liveDocs = liveDocs;
            this.termsEnum = termsEnum();
        }

        @Override
        public int ordValue() throws IOException {
            return in.ordValue();
        }

        @Override
        public BytesRef lookupOrd(int ord) throws IOException {
            termsEnum.seekExact(ord);
            return termsEnum.term();
        }

        @Override
        public int getValueCount() {
            return in.getValueCount();
        }

        @Override
        public boolean advanceExact(int target) throws IOException {
            return in.advanceExact(target);
        }

        @Override
        public int docID() {
            return in.docID();
        }

        @Override
        public int nextDoc() throws IOException {
            return in.nextDoc();
        }

        @Override
        public int advance(int target) throws IOException {
            return in.advance(target);
        }

        @Override
        public long cost() {
            return in.cost();
        }

        @Override
        public int lookupTerm(BytesRef key) throws IOException {
            return in.lookupTerm(key);
        }

        @Override
        public TermsEnum termsEnum() throws IOException {
            // this needs to be a fresh new TermsEnum
            if (invertedIndexTermsEnum == null) {
                // we can't cross check
                return new DocumentSafeTermsEnum(in.termsEnum());
            } else {
                return new DocumentSafeDocValuesTermsEnum(in.termsEnum(), invertedIndexTermsEnum, liveDocs);
            }
        }
    }

    static class DocumentSafeSortedSetDocValues extends SortedSetDocValues {

        private final SortedSetDocValues in;
        private final TermsEnum invertedIndexTermsEnum;
        private final Bits liveDocs;
        private final TermsEnum termsEnum;

        DocumentSafeSortedSetDocValues(SortedSetDocValues in, TermsEnum invertedIndexTermsEnum, Bits liveDocs) throws IOException {
            this.in = in;
            this.invertedIndexTermsEnum = invertedIndexTermsEnum;
            this.liveDocs = liveDocs;
            this.termsEnum = termsEnum();
        }

        @Override
        public long nextOrd() throws IOException {
            return in.nextOrd();
        }

        @Override
        public int docValueCount() {
            return in.docValueCount();
        }

        @Override
        public BytesRef lookupOrd(long ord) throws IOException {
            termsEnum.seekExact(ord);
            return termsEnum.term();
        }

        @Override
        public long getValueCount() {
            return in.getValueCount();
        }

        @Override
        public boolean advanceExact(int target) throws IOException {
            return in.advanceExact(target);
        }

        @Override
        public int docID() {
            return in.docID();
        }

        @Override
        public int nextDoc() throws IOException {
            return in.nextDoc();
        }

        @Override
        public int advance(int target) throws IOException {
            return in.advance(target);
        }

        @Override
        public long cost() {
            return in.cost();
        }

        @Override
        public long lookupTerm(BytesRef key) throws IOException {
            return in.lookupTerm(key);
        }

        @Override
        public TermsEnum termsEnum() throws IOException {
            // this needs to be a fresh new TermsEnum
            if (invertedIndexTermsEnum == null) {
                // we can't cross check
                return new DocumentSafeTermsEnum(in.termsEnum());
            } else {
                return new DocumentSafeDocValuesTermsEnum(in.termsEnum(), invertedIndexTermsEnum, liveDocs);
            }
        }
    }
}
