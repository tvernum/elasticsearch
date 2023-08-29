/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.common.util;

import org.apache.commons.codec.binary.Hex;
import org.elasticsearch.Build;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.VersionUtils;

import java.time.Instant;
import java.util.Properties;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

public class FeatureFlagTests extends ESTestCase {

    public void testSetFeatureFlagEnabledInReleaseBuild() {
        final Properties properties = setProperty("es.test_feature_flag_enabled", "true");
        final FeatureFlag flag = newFeatureFlag(properties, false);
        assertThat(flag.isEnabled(), is(true));
    }

    public void testSetFeatureFlagRegisteredInReleaseBuild() {
        final Properties properties = setProperty("es.test_feature_flag_registered", "true");
        final Build build = randomBuild(false);
        final FeatureFlag flag = new FeatureFlag("test", "registered", build, properties::getProperty);
        assertThat(flag.isEnabled(), is(true));
    }

    public void testSetFeatureFlagExplicitlyDisabledInReleaseBuild() {
        final Properties properties = setProperty("es.test_feature_flag_enabled", "false");
        final FeatureFlag flag = newFeatureFlag(properties, false);
        assertThat(flag.isEnabled(), is(false));
    }

    public void testSetFeatureFlagDefaultDisabledInReleaseBuild() {
        final Properties properties = new Properties();
        final FeatureFlag flag = newFeatureFlag(properties, false);
        assertThat(flag.isEnabled(), is(false));
    }

    public void testSetFeatureFlagDefaultEnabledInSnapshotBuild() {
        final Properties properties = randomBoolean() ? new Properties() : setProperty("es.feature_flag_default", "true");
        final FeatureFlag flag = newFeatureFlag(properties, true);
        assertThat(flag.isEnabled(), is(true));
    }

    public void testSetFeatureFlagExplicitlyEnabledInSnapshotBuild() {
        final Properties properties = setProperty("es.test_feature_flag_enabled", "true");
        final FeatureFlag flag = newFeatureFlag(properties, true);
        assertThat(flag.isEnabled(), is(true));
    }

    public void testSingleFeatureFlagCannotBeDisabledInSnapshotBuild() {
        final Properties properties = setProperty("es.test_feature_flag_enabled", "false");
        final IllegalArgumentException ex = expectThrows(IllegalArgumentException.class, () -> newFeatureFlag(properties, true));
        assertThat(ex.getMessage(), containsString("enabled by default"));
        assertThat(ex.getMessage(), containsString("cannot be disabled"));
    }

    public void testCanDisableAllFeatureFlagsInSnapshotBuild() {
        final Properties properties = setProperty("es.feature_flag_default", "false");
        final FeatureFlag flag = newFeatureFlag(properties, true);
        assertThat(flag.isEnabled(), is(false));
    }

    public void testCanDisableOnlyOneFeatureFlagInSnapshotBuild() {
        final Build build = randomBuild(true);
        final Properties properties = setProperties("es.feature_flag_default", "false", "es.test1_feature_flag_enabled", "true");

        final FeatureFlag flag1 = new FeatureFlag("test1", "enabled", build, properties::getProperty);
        assertThat(flag1.isEnabled(), is(true));

        final FeatureFlag flag2 = new FeatureFlag("test2", "enabled", build, properties::getProperty);
        assertThat(flag2.isEnabled(), is(false));
    }

    public void testCanEnableAllFeatureFlagsInReleaseBuild() {
        final Properties properties = setProperty("es.feature_flag_default", "true");
        final FeatureFlag flag = newFeatureFlag(properties, false);
        assertThat(flag.isEnabled(), is(true));
    }

    private static FeatureFlag newFeatureFlag(Properties properties, boolean isSnapshot) {
        final Build build = randomBuild(isSnapshot);
        return new FeatureFlag("test", "enabled", build, properties::getProperty);
    }

    private static Properties setProperty(String key, String value) {
        Properties properties = new Properties();
        properties.setProperty(key, value);
        return properties;
    }

    private static Properties setProperties(String... nameAndValue) {
        if (nameAndValue.length % 2 != 0) {
            throw new IllegalArgumentException("Must have an even number of arguments");
        }
        Properties properties = new Properties();
        for (int i = 0; i < nameAndValue.length; i += 2) {
            properties.setProperty(nameAndValue[i], nameAndValue[i + 1]);
        }
        return properties;
    }

    private static Build randomBuild(boolean isSnapshot) {
        return new Build(
            randomFrom("flavor1", "flavor2"),
            randomFrom(Build.Type.values()),
            Hex.encodeHexString(randomByteArrayOfLength(20)),
            Instant.now().toString(),
            isSnapshot,
            VersionUtils.randomVersion(random()).toString(),
            VersionUtils.randomVersion(random()).toString(),
            VersionUtils.randomVersion(random()).toString(),
            randomAlphaOfLength(10)
        );
    }

}
