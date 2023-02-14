/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.license;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.AckedClusterStateUpdateTask;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateUpdateTask;
import org.elasticsearch.cluster.ack.AckedRequest;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.SuppressForbidden;
import org.elasticsearch.gateway.GatewayService;
import org.elasticsearch.protocol.xpack.license.LicensesStatus;
import org.elasticsearch.protocol.xpack.license.PutLicenseResponse;
import org.elasticsearch.xpack.core.XPackPlugin;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class ClusterLicenseStore implements LicenseStore {
    public static final ClusterLicenseStore INSTANCE = new ClusterLicenseStore();
    private static final Logger logger = LogManager.getLogger(ClusterLicenseStore.class);

    @Override
    public StoredLicenseState resolveLicenseState(ClusterChangedEvent event) {
        final ClusterState previousClusterState = event.previousState();
        final ClusterState currentClusterState = event.state();

        return resolveLicenseState(Optional.of(previousClusterState), currentClusterState);
    }

    @Override
    public StoredLicenseState resolveLicenseState(ClusterState clusterState) {
        return resolveLicenseState(Optional.empty(), clusterState);
    }

    @Override
    public Optional<License> resolveLicense(Metadata clusterMetadata) {
        return getLicenseMetadata(clusterMetadata).map(LicensesMetadata::getLicense);
    }

    private StoredLicenseState resolveLicenseState(Optional<ClusterState> previousClusterState, ClusterState currentClusterState) {
        if (currentClusterState.blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK)) {
            logger.debug("skipped license notifications reason: [{}]", GatewayService.STATE_NOT_RECOVERED_BLOCK);
            return StoredLicenseState.NOT_READY;
        }

        if (XPackPlugin.isReadyForXPackCustomMetadata(currentClusterState) == false) {
            logger.debug(
                "cannot add license to cluster as the following nodes might not understand the license metadata: {}",
                () -> XPackPlugin.nodesNotReadyForXPackCustomMetadata(currentClusterState)
            );
            return StoredLicenseState.NOT_READY;
        }

        final Optional<LicensesMetadata> prevLicensesMetadata = previousClusterState.filter(
            s -> s.blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK) == false
        ).map(s -> s.getMetadata().<LicensesMetadata>custom(LicensesMetadata.TYPE));
        final Optional<LicensesMetadata> currentLicensesMetadata = getLicenseMetadata(currentClusterState.getMetadata());
        if (prevLicensesMetadata.isEmpty()) {
            if (currentLicensesMetadata.isPresent()) {
                logger.debug("state recovered: previous license [{}]", prevLicensesMetadata);
                logger.debug("state recovered: current license [{}]", currentLicensesMetadata);
                return resolveState(currentLicensesMetadata);
            } else {
                logger.trace("state recovered: no current license");
            }
        } else if (prevLicensesMetadata.equals(currentLicensesMetadata) == false) {
            logger.debug("previous [{}]", prevLicensesMetadata);
            logger.debug("current [{}]", currentLicensesMetadata);
            return resolveState(currentLicensesMetadata);
        } else {
            logger.trace("license unchanged [{}]", currentLicensesMetadata);
        }

        for (var licensesMetadata : List.of(currentLicensesMetadata, prevLicensesMetadata)) {
            License license = licensesMetadata.map(LicensesMetadata::getLicense).orElse(null);
            if (license != null) {
                return StoredLicenseState.licenseAvailable(license);
            }
        }
        return StoredLicenseState.READY_NO_LICENSE;
    }

    private static Optional<LicensesMetadata> getLicenseMetadata(Metadata metadata) {
        return Optional.ofNullable(metadata.custom(LicensesMetadata.TYPE));
    }

    private StoredLicenseState resolveState(Optional<LicensesMetadata> currentLicensesMetadata) {
        return currentLicensesMetadata.map(this::getLicense)
            .filter(Objects::nonNull)
            .map(StoredLicenseState::licenseAvailable)
            .orElse(StoredLicenseState.READY_NO_LICENSE);
    }

    private License getLicense(@Nullable final LicensesMetadata metadata) {
        if (metadata == null) {
            return null;
        }

        License license = metadata.getLicense();
        if (license == LicensesMetadata.LICENSE_TOMBSTONE) {
            return license;
        }
        if (license != null && license.verified()) {
            return license;
        }
        return null;
    }

    /**
     * Master-only operation to generate a one-time global self generated license.
     * The self generated license is only generated and stored if the current cluster state metadata
     * has no existing license. If the cluster currently has a basic license that has an expiration date,
     * a new basic license with no expiration date is generated.
     */
    @Override
    public void installAutomaticLicense(Settings settings, ClusterService clusterService, Clock clock) {
        submitUnbatchedTask(
            clusterService,
            StartupSelfGeneratedLicenseTask.TASK_SOURCE,
            new StartupSelfGeneratedLicenseTask(settings, clock, clusterService)
        );
    }

    @Override
    public void storeLicense(
        ClusterService clusterService,
        License newLicense,
        AckedRequest request,
        ActionListener<PutLicenseResponse> listener
    ) {
        submitUnbatchedTask(
            clusterService,
            "register license [" + newLicense.uid() + "]",
            new AckedClusterStateUpdateTask(request, listener) {
                @Override
                protected PutLicenseResponse newResponse(boolean acknowledged) {
                    return new PutLicenseResponse(acknowledged, LicensesStatus.VALID);
                }

                @Override
                public ClusterState execute(ClusterState currentState) throws Exception {
                    XPackPlugin.checkReadyForXPackCustomMetadata(currentState);
                    final Version oldestNodeVersion = currentState.nodes().getSmallestNonClientNodeVersion();
                    if (licenseIsCompatible(newLicense, oldestNodeVersion) == false) {
                        throw new IllegalStateException(
                            "The provided license is not compatible with node version [" + oldestNodeVersion + "]"
                        );
                    }
                    final Metadata currentMetadata = currentState.metadata();
                    final Optional<LicensesMetadata> licensesMetadata = getLicenseMetadata(currentMetadata);
                    final Version trialVersion = licensesMetadata.map(lm -> lm.getMostRecentTrialVersion()).orElse(null);
                    final Metadata.Builder mdBuilder = Metadata.builder(currentMetadata);
                    mdBuilder.putCustom(LicensesMetadata.TYPE, new LicensesMetadata(newLicense, trialVersion));
                    return ClusterState.builder(currentState).metadata(mdBuilder).build();
                }
            }
        );
    }

    @SuppressForbidden(reason = "legacy usage of unbatched task") // TODO add support for batching here
    private void submitUnbatchedTask(
        ClusterService clusterService,
        @SuppressWarnings("SameParameterValue") String source,
        ClusterStateUpdateTask task
    ) {
        clusterService.submitUnbatchedStateUpdateTask(source, task);
    }

    private static boolean licenseIsCompatible(License license, Version version) {
        final int maxVersion = LicenseUtils.getMaxLicenseVersion(version);
        return license.version() <= maxVersion;
    }
}
