/*
 * ELASTICSEARCH CONFIDENTIAL
 * __________________
 *
 *  [2018] Elasticsearch Incorporated. All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Elasticsearch Incorporated and its suppliers,
 * if any.  The intellectual and technical concepts contained
 * herein are proprietary to Elasticsearch Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Elasticsearch Incorporated.
 */

package org.elasticsearch.xpack.core.security.authc.support;

import org.elasticsearch.common.settings.Setting;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

public class LookupRealmSettings {

    // TODO: A better name for this config setting
    public static final Setting<List<String>> LOOKUP_REALMS = Setting.listSetting("lookup_realms",
        Collections.emptyList(), Function.identity(), Setting.Property.NodeScope);

    public static Collection<Setting<?>> getSettings() {
        return Collections.singleton(LOOKUP_REALMS);
    }
}
