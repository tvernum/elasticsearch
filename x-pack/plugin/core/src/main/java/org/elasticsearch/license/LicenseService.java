/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.license;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.SetOnce;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.ClusterStateTaskConfig;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Priority;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.component.Lifecycle;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.logging.LoggerMessageFormat;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.time.DateFormatter;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.protocol.xpack.XPackInfoResponse;
import org.elasticsearch.protocol.xpack.license.LicenseStatus;
import org.elasticsearch.protocol.xpack.license.LicensesStatus;
import org.elasticsearch.protocol.xpack.license.PutLicenseResponse;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.scheduler.SchedulerEngine;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Service responsible for managing {@link LicensesMetadata}.
 * <p>
 * On the master node, the service handles updating the cluster state when a new license is registered.
 * It also listens on all nodes for cluster state updates, and updates {@link XPackLicenseState} when
 * the license changes are detected in the cluster state.
 */
public class LicenseService extends AbstractLifecycleComponent implements ClusterStateListener, SchedulerEngine.Listener {
    private static final Logger logger = LogManager.getLogger(LicenseService.class);

    public static final Setting<License.LicenseType> SELF_GENERATED_LICENSE_TYPE = new Setting<>(
        "xpack.license.self_generated.type",
        License.LicenseType.BASIC.getTypeName(),
        (s) -> {
            final License.LicenseType type = License.LicenseType.parse(s);
            return SelfGeneratedLicense.validateSelfGeneratedType(type);
        },
        Setting.Property.NodeScope
    );

    public static final List<License.LicenseType> ALLOWABLE_UPLOAD_TYPES = getAllowableUploadTypes();

    public static final Setting<List<License.LicenseType>> ALLOWED_LICENSE_TYPES_SETTING = Setting.listSetting(
        "xpack.license.upload.types",
        ALLOWABLE_UPLOAD_TYPES.stream().map(License.LicenseType::getTypeName).toList(),
        License.LicenseType::parse,
        LicenseService::validateUploadTypesSetting,
        Setting.Property.NodeScope
    );

    // pkg private for tests
    static final TimeValue NON_BASIC_SELF_GENERATED_LICENSE_DURATION = TimeValue.timeValueHours(30 * 24);

    static final Set<License.LicenseType> VALID_TRIAL_TYPES = Set.of(
        License.LicenseType.GOLD,
        License.LicenseType.PLATINUM,
        License.LicenseType.ENTERPRISE,
        License.LicenseType.TRIAL
    );

    /**
     * Period before the license expires when warning starts being added to the response header
     */
    static final TimeValue LICENSE_EXPIRATION_WARNING_PERIOD = days(7);

    public static final long BASIC_SELF_GENERATED_LICENSE_EXPIRATION_MILLIS =
        XPackInfoResponse.BASIC_SELF_GENERATED_LICENSE_EXPIRATION_MILLIS;

    private static final SetOnce<LicenseStore> store = new SetOnce<>();

    private final Settings settings;

    private final ClusterService clusterService;

    /**
     * The xpack feature state to update when license changes are made.
     */
    private final XPackLicenseState licenseState;

    /**
     * Currently active license
     */
    private final AtomicReference<License> currentLicenseHolder = new AtomicReference<>();
    private final SchedulerEngine scheduler;
    private final Clock clock;

    /**
     * Callbacks to notify relative to license expiry
     */
    private final List<ExpirationCallback> expirationCallbacks = new ArrayList<>();

    /**
     * Which license types are permitted to be uploaded to the cluster
     * @see #ALLOWED_LICENSE_TYPES_SETTING
     */
    private final List<License.LicenseType> allowedLicenseTypes;

    private final StartTrialClusterTask.Executor startTrialExecutor = new StartTrialClusterTask.Executor();
    private final StartBasicClusterTask.Executor startBasicExecutor = new StartBasicClusterTask.Executor();

    /**
     * Max number of nodes licensed by generated trial license
     */
    static final int SELF_GENERATED_LICENSE_MAX_NODES = 1000;
    static final int SELF_GENERATED_LICENSE_MAX_RESOURCE_UNITS = SELF_GENERATED_LICENSE_MAX_NODES;

    public static final String LICENSE_JOB = "licenseJob";

    public static final DateFormatter DATE_FORMATTER = DateFormatter.forPattern("EEEE, MMMM dd, yyyy");

    private static final String ACKNOWLEDGEMENT_HEADER = "This license update requires acknowledgement. To acknowledge the license, "
        + "please read the following messages and update the license again, this time with the \"acknowledge=true\" parameter:";

    public LicenseService(
        Settings settings,
        ThreadPool threadPool,
        ClusterService clusterService,
        Clock clock,
        XPackLicenseState licenseState
    ) {
        this.settings = settings;
        this.clusterService = clusterService;
        this.clock = clock;
        this.licenseState = licenseState;
        this.scheduler = new SchedulerEngine(settings, clock);
        this.allowedLicenseTypes = ALLOWED_LICENSE_TYPES_SETTING.get(settings);
        this.scheduler.register(this);
        populateExpirationCallbacks();

        threadPool.scheduleWithFixedDelay(licenseState::cleanupUsageTracking, TimeValue.timeValueHours(1), ThreadPool.Names.GENERIC);
    }

    private static LicenseStore getStore() {
        if (store.get() == null) {
            return ClusterLicenseStore.INSTANCE;
        } else {
            return store.get();
        }
    }

    public static void setStore(LicenseStore newStore) {
        store.set(newStore);
    }

    private void logExpirationWarning(long expirationMillis, boolean expired) {
        logger.warn("{}", buildExpirationMessage(expirationMillis, expired));
    }

    static CharSequence buildExpirationMessage(long expirationMillis, boolean expired) {
        String expiredMsg = expired ? "expired" : "will expire";
        String general = LoggerMessageFormat.format(null, """
            License [{}] on [{}].
            # If you have a new license, please update it. Otherwise, please reach out to
            # your support contact.
            #\s""", expiredMsg, DATE_FORMATTER.formatMillis(expirationMillis));
        if (expired) {
            general = general.toUpperCase(Locale.ROOT);
        }
        StringBuilder builder = new StringBuilder(general);
        builder.append(System.lineSeparator());
        if (expired) {
            builder.append("# COMMERCIAL PLUGINS OPERATING WITH REDUCED FUNCTIONALITY");
        } else {
            builder.append("# Commercial plugins operate with reduced functionality on license expiration:");
        }
        XPackLicenseState.EXPIRATION_MESSAGES.forEach((feature, messages) -> {
            if (messages.length > 0) {
                builder.append(System.lineSeparator());
                builder.append("# - ");
                builder.append(feature);
                for (String message : messages) {
                    builder.append(System.lineSeparator());
                    builder.append("#  - ");
                    builder.append(message);
                }
            }
        });
        return builder;
    }

    private void populateExpirationCallbacks() {
        expirationCallbacks.add(new ExpirationCallback.Pre(days(0), days(25), days(1)) {
            @Override
            public void on(License license) {
                logExpirationWarning(getExpiryDate(license), false);
            }
        });
        expirationCallbacks.add(new ExpirationCallback.Post(days(0), null, TimeValue.timeValueMinutes(10)) {
            @Override
            public void on(License license) {
                logExpirationWarning(getExpiryDate(license), true);
            }
        });
    }

    /**
     * Gets the effective expiry date of the given license, including any overrides.
     */
    public static long getExpiryDate(License license) {
        String licenseUidHash = MessageDigests.toHexString(MessageDigests.sha256().digest(license.uid().getBytes(StandardCharsets.UTF_8)));
        return LicenseOverrides.overrideDateForLicense(licenseUidHash)
            .map(date -> date.toInstant().toEpochMilli())
            .orElse(license.expiryDate());
    }

    /**
     * Gets the current status of a license
     */
    public static LicenseStatus status(License license) {
        long now = System.currentTimeMillis();
        if (license.issueDate() > now) {
            return LicenseStatus.INVALID;
        } else if (LicenseService.getExpiryDate(license) < now) {
            return LicenseStatus.EXPIRED;
        }
        return LicenseStatus.ACTIVE;
    }

    /**
     * Registers new license in the cluster
     * Master only operation. Installs a new license on the master provided it is VALID
     */
    public void registerLicense(final PutLicenseRequest request, final ActionListener<PutLicenseResponse> listener) {
        final License newLicense = request.license();
        final long now = clock.millis();
        if (LicenseVerifier.verifyLicense(newLicense) == false || newLicense.issueDate() > now || newLicense.startDate() > now) {
            listener.onResponse(new PutLicenseResponse(true, LicensesStatus.INVALID));
            return;
        }
        final License.LicenseType licenseType;
        try {
            licenseType = License.LicenseType.resolve(newLicense);
        } catch (Exception e) {
            listener.onFailure(e);
            return;
        }
        if (licenseType == License.LicenseType.BASIC) {
            listener.onFailure(new IllegalArgumentException("Registering basic licenses is not allowed."));
        } else if (isAllowedLicenseType(licenseType) == false) {
            listener.onFailure(
                new IllegalArgumentException("Registering [" + licenseType.getTypeName() + "] licenses is not allowed on this cluster")
            );
        } else if (getExpiryDate(newLicense) < now) {
            listener.onResponse(new PutLicenseResponse(true, LicensesStatus.EXPIRED));
        } else {
            if (request.acknowledged() == false) {
                // TODO: ack messages should be generated on the master, since another node's cluster state may be behind...
                final License currentLicense = getLicense();
                if (currentLicense != null) {
                    Map<String, String[]> acknowledgeMessages = getAckMessages(newLicense, currentLicense);
                    if (acknowledgeMessages.isEmpty() == false) {
                        // needs acknowledgement
                        listener.onResponse(
                            new PutLicenseResponse(false, LicensesStatus.VALID, ACKNOWLEDGEMENT_HEADER, acknowledgeMessages)
                        );
                        return;
                    }
                }
            }

            // This check would be incorrect if "basic" licenses were allowed here
            // because the defaults there mean that security can be "off", even if the setting is "on"
            // BUT basic licenses are explicitly excluded earlier in this method, so we don't need to worry
            if (XPackSettings.SECURITY_ENABLED.get(settings)) {
                if (XPackSettings.FIPS_MODE_ENABLED.get(settings)
                    && false == XPackLicenseState.isFipsAllowedForOperationMode(newLicense.operationMode())) {
                    throw new IllegalStateException(
                        "Cannot install a [" + newLicense.operationMode() + "] license unless FIPS mode is disabled"
                    );
                }
            }

            getStore().storeLicense(clusterService, newLicense, request, listener);
        }
    }

    private boolean isAllowedLicenseType(License.LicenseType type) {
        logger.debug("Checking license [{}] against allowed license types: {}", type, allowedLicenseTypes);
        return allowedLicenseTypes.contains(type);
    }

    public static Map<String, String[]> getAckMessages(License newLicense, License currentLicense) {
        Map<String, String[]> acknowledgeMessages = new HashMap<>();
        if (License.isAutoGeneratedLicense(currentLicense.signature()) == false // current license is not auto-generated
            && currentLicense.issueDate() > newLicense.issueDate()) { // and has a later issue date
            acknowledgeMessages.put(
                "license",
                new String[] {
                    "The new license is older than the currently installed license. "
                        + "Are you sure you want to override the current license?" }
            );
        }
        XPackLicenseState.ACKNOWLEDGMENT_MESSAGES.forEach((feature, ackMessages) -> {
            String[] messages = ackMessages.apply(currentLicense.operationMode(), newLicense.operationMode());
            if (messages.length > 0) {
                acknowledgeMessages.put(feature, messages);
            }
        });
        return acknowledgeMessages;
    }

    private static TimeValue days(int days) {
        return TimeValue.timeValueHours(days * 24);
    }

    @Override
    public void triggered(SchedulerEngine.Event event) {
        final ClusterLicenseStore.StoredLicenseState storedLicenseState = getStore().resolveLicenseState(clusterService.state());
        storedLicenseState.license.ifPresent(license -> {
            if (event.getJobName().equals(LICENSE_JOB)) {
                updateLicenseState(license);
            } else if (event.getJobName().startsWith(ExpirationCallback.EXPIRATION_JOB_PREFIX)) {
                expirationCallbacks.stream()
                    .filter(expirationCallback -> expirationCallback.getId().equals(event.getJobName()))
                    .forEach(expirationCallback -> expirationCallback.on(license));
            }
        });
    }

    /**
     * Remove license from the cluster state metadata
     */
    public void removeLicense(final ActionListener<PostStartBasicResponse> listener) {
        final PostStartBasicRequest startBasicRequest = new PostStartBasicRequest().acknowledge(true);
        final StartBasicClusterTask task = new StartBasicClusterTask(
            logger,
            clusterService.getClusterName().value(),
            clock,
            startBasicRequest,
            "delete license",
            listener
        );
        clusterService.submitStateUpdateTask(
            task.getDescription(),
            task,
            ClusterStateTaskConfig.build(Priority.NORMAL), // TODO should pass in request.masterNodeTimeout() here
            startBasicExecutor
        );
    }

    public License getLicense() {
        return getLicense(clusterService.state());
    }

    public static License getLicense(ClusterState state) {
        if (getStore() == null) {
            return null;
        }
        return getStore().resolveLicenseState(state).license.filter(lic -> lic != LicensesMetadata.LICENSE_TOMBSTONE).orElse(null);
    }

    public static License getLicense(Metadata metadata) {
        if (getStore() == null) {
            return null;
        }
        return getStore().resolveLicense(metadata).filter(lic -> lic != LicensesMetadata.LICENSE_TOMBSTONE).orElse(null);
    }

    void startTrialLicense(PostStartTrialRequest request, final ActionListener<PostStartTrialResponse> listener) {
        License.LicenseType requestedType = License.LicenseType.parse(request.getType());
        if (VALID_TRIAL_TYPES.contains(requestedType) == false) {
            throw new IllegalArgumentException(
                "Cannot start trial of type ["
                    + requestedType.getTypeName()
                    + "]. Valid trial types are ["
                    + VALID_TRIAL_TYPES.stream().map(License.LicenseType::getTypeName).sorted().collect(Collectors.joining(","))
                    + "]"
            );
        }
        clusterService.submitStateUpdateTask(
            StartTrialClusterTask.TASK_SOURCE,
            new StartTrialClusterTask(logger, clusterService.getClusterName().value(), clock, request, listener),
            ClusterStateTaskConfig.build(Priority.NORMAL), // TODO should pass in request.masterNodeTimeout() here
            startTrialExecutor
        );
    }

    void startBasicLicense(PostStartBasicRequest request, final ActionListener<PostStartBasicResponse> listener) {
        StartBasicClusterTask task = new StartBasicClusterTask(
            logger,
            clusterService.getClusterName().value(),
            clock,
            request,
            "start basic license",
            listener
        );
        clusterService.submitStateUpdateTask(
            task.getDescription(),
            task,
            ClusterStateTaskConfig.build(Priority.NORMAL), // TODO should pass in request.masterNodeTimeout() here
            startBasicExecutor
        );
    }

    @Override
    protected void doStart() throws ElasticsearchException {
        clusterService.addListener(this);
        scheduler.start(Collections.emptyList());
        logger.debug("initializing license state");
        if (clusterService.lifecycleState() == Lifecycle.State.STARTED) {
            var clusterState = clusterService.state();
            if (clusterState.getNodes().isLocalNodeElectedMaster()) {
                var storedLicenseState = getStore().resolveLicenseState(clusterState);
                maybeUpdateLicense(storedLicenseState, clusterState.nodes());
            }
        }
    }

    @Override
    protected void doStop() throws ElasticsearchException {
        clusterService.removeListener(this);
        scheduler.stop();
        // clear current license
        currentLicenseHolder.set(null);
    }

    @Override
    protected void doClose() throws ElasticsearchException {}

    /**
     * When there is no global block on {@link org.elasticsearch.gateway.GatewayService#STATE_NOT_RECOVERED_BLOCK}
     * notify licensees and issue auto-generated license if no license has been installed/issued yet.
     */
    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        var state = getStore().resolveLicenseState(event);
        if (state.storeReady == false) {
            return;
        }
        state.license.ifPresent(this::checkForNewLicense);

        var nodes = event.state().getNodes();
        maybeUpdateLicense(state, nodes);
    }

    private void maybeUpdateLicense(ClusterLicenseStore.StoredLicenseState storedLicenseState, DiscoveryNodes nodes) {
        if (storedLicenseState.storeReady && nodes.isLocalNodeElectedMaster() && needsNewLicense(storedLicenseState.license, nodes)) {
            getStore().installAutomaticLicense(settings, clusterService, clock);
        }
    }

    private boolean needsNewLicense(Optional<License> license, DiscoveryNodes nodes) {
        if (license.isEmpty()) {
            return true;
        }
        if (LicenseUtils.licenseNeedsExtended(license.get())) {
            return true;
        }
        if (LicenseUtils.signatureNeedsUpdate(license.get(), nodes)) {
            return true;
        }
        return false;
    }

    protected static String getExpiryWarning(long licenseExpiryDate, long currentTime) {
        final long diff = licenseExpiryDate - currentTime;
        if (LICENSE_EXPIRATION_WARNING_PERIOD.getMillis() > diff) {
            final long days = TimeUnit.MILLISECONDS.toDays(diff);
            final String expiryMessage = (days == 0 && diff > 0)
                ? "expires today"
                : (diff > 0
                    ? String.format(Locale.ROOT, "will expire in [%d] days", days)
                    : String.format(Locale.ROOT, "expired on [%s]", LicenseService.DATE_FORMATTER.formatMillis(licenseExpiryDate)));
            return "Your license "
                + expiryMessage
                + ". "
                + "Contact your administrator or update your license for continued use of features";
        }
        return null;
    }

    protected void updateLicenseState(final License license) {
        long time = clock.millis();
        if (license == LicensesMetadata.LICENSE_TOMBSTONE) {
            // implies license has been explicitly deleted
            licenseState.update(License.OperationMode.MISSING, false, getExpiryWarning(getExpiryDate(license), time));
            return;
        }
        if (license != null) {
            final boolean active;
            if (getExpiryDate(license) == BASIC_SELF_GENERATED_LICENSE_EXPIRATION_MILLIS) {
                active = true;
            } else {
                active = time >= license.issueDate() && time < getExpiryDate(license);
            }
            licenseState.update(license.operationMode(), active, getExpiryWarning(getExpiryDate(license), time));

            if (active) {
                logger.debug("license [{}] - valid", license.uid());
            } else {
                logger.warn("license [{}] - expired", license.uid());
            }
        }
    }

    private void checkForNewLicense(License license) {
        // license can be null if the trial license is yet to be auto-generated
        // in this case, it is a no-op
        if (license != null) {
            final License previousLicense = currentLicenseHolder.get();
            if (license.equals(previousLicense) == false) {
                currentLicenseHolder.set(license);
                scheduler.add(new SchedulerEngine.Job(LICENSE_JOB, nextLicenseCheck(license)));
                for (ExpirationCallback expirationCallback : expirationCallbacks) {
                    scheduler.add(
                        new SchedulerEngine.Job(
                            expirationCallback.getId(),
                            (startTime, now) -> expirationCallback.nextScheduledTimeForExpiry(getExpiryDate(license), startTime, now)
                        )
                    );
                }
                if (previousLicense != null) {
                    // remove operationModeFileWatcher to gc the old license object
                    previousLicense.removeOperationModeFileWatcher();
                }
                logger.info("license [{}] mode [{}] - valid", license.uid(), license.operationMode().name().toLowerCase(Locale.ROOT));
                updateLicenseState(license);
            }
        }
    }

    // pkg private for tests
    static SchedulerEngine.Schedule nextLicenseCheck(License license) {
        return (startTime, time) -> {
            if (time < license.issueDate()) {
                // when we encounter a license with a future issue date
                // which can happen with autogenerated license,
                // we want to schedule a notification on the license issue date
                // so the license is notified once it is valid
                // see https://github.com/elastic/x-plugins/issues/983
                return license.issueDate();
            } else if (time < getExpiryDate(license)) {
                // Re-check the license every day during the warning period up to the license expiration.
                // This will cause the warning message to be updated that is emitted on soon-expiring license use.
                long nextTime = getExpiryDate(license) - LICENSE_EXPIRATION_WARNING_PERIOD.getMillis();
                while (nextTime <= time) {
                    nextTime += TimeValue.timeValueDays(1).getMillis();
                }
                return nextTime;
            }
            return -1; // license is expired, no need to check again
        };
    }

    private static List<License.LicenseType> getAllowableUploadTypes() {
        return Stream.of(License.LicenseType.values()).filter(t -> t != License.LicenseType.BASIC).toList();
    }

    private static void validateUploadTypesSetting(List<License.LicenseType> value) {
        if (ALLOWABLE_UPLOAD_TYPES.containsAll(value) == false) {
            throw new IllegalArgumentException(
                "Invalid value ["
                    + value.stream().map(License.LicenseType::getTypeName).collect(Collectors.joining(","))
                    + "] for "
                    + ALLOWED_LICENSE_TYPES_SETTING.getKey()
                    + ", allowed values are ["
                    + ALLOWABLE_UPLOAD_TYPES.stream().map(License.LicenseType::getTypeName).collect(Collectors.joining(","))
                    + "]"
            );
        }
    }
}
