/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.license;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ack.AckedRequest;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.protocol.xpack.license.PutLicenseResponse;

import java.time.Clock;
import java.util.Optional;

public interface LicenseStore {
    StoredLicenseState resolveLicenseState(ClusterChangedEvent event);

    StoredLicenseState resolveLicenseState(ClusterState clusterState);

    Optional<License> resolveLicense(Metadata clusterMetadata);

    void installAutomaticLicense(Settings settings, ClusterService clusterService, Clock clock);

    void storeLicense(ClusterService clusterService, License newLicense, AckedRequest request, ActionListener<PutLicenseResponse> listener);

    class StoredLicenseState {
        final boolean storeReady;
        final Optional<License> license;

        private StoredLicenseState(boolean storeReady, Optional<License> license) {
            this.storeReady = storeReady;
            this.license = license;
        }

        public static final StoredLicenseState NOT_READY = new StoredLicenseState(false, Optional.empty());
        public static final StoredLicenseState READY_NO_LICENSE = new StoredLicenseState(true, Optional.empty());

        public static StoredLicenseState licenseAvailable(License license) {
            return new StoredLicenseState(true, Optional.of(license));
        }
    }
}
