/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.benchmark.xcontent;

import org.elasticsearch.core.Glob;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

@Fork(1)
@Warmup(iterations = 1)
@Measurement(iterations = 3)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
public class GlobBenchmark {

    private String[] fields;
    private String[] multipleAsterisk;

    @Setup
    public void setup() {
        fields = new String[] {
            "hits",
            "metadata",
            "indices",
            "errors",
            "total",
            "aggregations",
            "default",
            "settings",
            "logs-nginx",
            "metrics-nginx",
            "logs-mysql",
            "metrics-mysql",
            "logs-nginx-20200101",
            "metrics-nginx-20200101",
            "logs-mysql-20200101",
            "metrics-mysql-20200101", };
        multipleAsterisk = IntStream.rangeClosed(1, 20).map(i -> i * 5).mapToObj("*"::repeat).toArray(String[]::new);
    }

    @Benchmark
    public void singleAsterisk() {
        glob("*");
    }

    @Benchmark
    public void multipleAsterisk() {
        for (var pattern : multipleAsterisk) {
            glob(pattern);
        }
    }

    @Benchmark
    public void prefix() {
        glob("logs-*");
        glob("metrics-*");
        glob("met*");
        glob("agg*");
    }

    @Benchmark
    public void infix() {
        glob("*-nginx-*");
        glob("*-mysql-*");
        glob("*data*");
    }

    @Benchmark
    public void suffix() {
        glob("*-mysql");
        glob("*-nginx");
        glob("*-20200101");
    }

    @Benchmark
    public void complex() {
        glob("logs-*-2020*");
        glob("logs-*-20200101");
        glob("logs-*-2020*01");
        glob("*-*-*");
        glob("*-*-2020*");
        glob("*-*-20*01*");
    }

    @Benchmark
    public void pathological() {
        glob("m**e**t**2*******0*****1*********");
        glob("****************et************i**n**************g**************");
    }

    private void glob(String pattern) {
        for (var str : fields) {
            Glob.globMatch(pattern, str);
        }
    }
}
