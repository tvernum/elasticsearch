/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ack.AckedRequest;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.license.License;
import org.elasticsearch.license.LicenseStore;
import org.elasticsearch.protocol.xpack.license.PutLicenseResponse;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

public class FixedLicenseStore implements LicenseStore {

    private AtomicReference<Tuple<String, License>> license = new AtomicReference<>();

    private License getLicense(Metadata metadata) {
        String clusterUUID = metadata.clusterUUID();
        for (;;) {
            var tup = license.get();

            if (tup != null && tup.v1().equals(clusterUUID)) {
                return tup.v2();
            }

            var newLicense = buildLicense(clusterUUID);
            Tuple<String, License> newState = new Tuple<>(clusterUUID, newLicense);
            if (license.compareAndSet(tup, newState)) {
                return newLicense;
            }
            // else, try again
        }
    }

    private License buildLicense(String clusterUUID) {
        return new License.Builder().type(License.LicenseType.ENTERPRISE)
            .issueDate(Instant.parse("2000-01-01T00:00:00Z").toEpochMilli())
            .startDate(Instant.now().toEpochMilli())
            .expiryDate(Instant.parse("2100-01-01T00:00:00Z").toEpochMilli())
            .maxResourceUnits(999)
            .issuedTo("elastic")
            .issuer("elastic")
            .uid(UUID.nameUUIDFromBytes(clusterUUID.getBytes(StandardCharsets.UTF_8)).toString())
            .build();
    }

    @Override
    public StoredLicenseState resolveLicenseState(ClusterChangedEvent event) {
        return StoredLicenseState.licenseAvailable(getLicense(event.state().metadata()));
    }

    @Override
    public StoredLicenseState resolveLicenseState(ClusterState clusterState) {
        return StoredLicenseState.licenseAvailable(getLicense(clusterState.metadata()));
    }

    @Override
    public Optional<License> resolveLicense(Metadata clusterMetadata) {
        return Optional.of(getLicense(clusterMetadata));
    }

    @Override
    public void installAutomaticLicense(Settings settings, ClusterService clusterService, Clock clock) {
        // no-op
    }

    @Override
    public void storeLicense(
        ClusterService clusterService,
        License newLicense,
        AckedRequest request,
        ActionListener<PutLicenseResponse> listener
    ) {
        throw new UnsupportedOperationException("Cannot install a license");
    }
}
