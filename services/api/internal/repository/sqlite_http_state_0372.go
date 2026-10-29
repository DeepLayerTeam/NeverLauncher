// SQLite-backed HTTP repository state. Generated from the MemoryRepository state
// fields to guarantee that an added mutable field cannot silently become volatile.
// This state is persisted atomically in a FULL-sync WAL transaction after mutations.
package repository

import (
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"time"
)

type sqliteHTTPState0372 struct {
	ManagedProviders               map[string]ManagedProviderHead02910      `json:"managedProviders"`
	HwidObservations               map[string]HWIDObservation0299           `json:"hwidObservations"`
	HwidAppeals                    map[string]HWIDAppeal0299                `json:"hwidAppeals"`
	ProtectionBans                 map[string]ProtectionBan                 `json:"protectionBans"`
	BuildWorkspaces                map[string]BuildWorkspace                `json:"buildWorkspaces"`
	OfficialProviderHistory        []OfficialProviderRevision02611          `json:"officialProviderHistory"`
	OperationalConfigRevisions     []OperationalConfigRevision              `json:"operationalConfigRevisions"`
	ReleaseDrafts                  map[string]ReleaseDraft                  `json:"releaseDrafts"`
	ChannelHeads                   map[string]model.ChannelHead             `json:"channelHeads"`
	DurableJobs                    map[string]model.DurableJob              `json:"durableJobs"`
	DurableOpAttempts              map[string][]model.DurableJobAttempt     `json:"durableOpAttempts"`
	DurableJobKeys                 map[string]string                        `json:"durableJobKeys"`
	DurableScopeLeases             map[string]model.DurableScopeLease       `json:"durableScopeLeases"`
	DurableOutbox                  map[string]model.DurableOutboxEvent      `json:"durableOutbox"`
	DurableNonces                  map[string]time.Time                     `json:"durableNonces"`
	IdempotencyDigests             map[string]string                        `json:"idempotencyDigests"`
	Projects                       []model.Project                          `json:"projects"`
	ProfileHistory                 map[string][]model.ProfileSnapshot       `json:"profileHistory"`
	Profiles                       []model.Profile                          `json:"profiles"`
	Channels                       []model.ReleaseChannel                   `json:"channels"`
	Releases                       []model.ReleaseVersion                   `json:"releases"`
	IntegrityChecks                []model.IntegrityCheckResult             `json:"integrityChecks"`
	RuntimeValidations             []model.RuntimeValidationResult          `json:"runtimeValidations"`
	StagedRuntimeRuns0342          []model.StagedRuntimeRun0342             `json:"stagedRuntimeRuns0342"`
	ValidationAttestations0345     []model.ValidationAttestation0345        `json:"validationAttestations0345"`
	ValidationAttempts03412        []model.ValidationAttempt03412           `json:"validationAttempts03412"`
	ValidationChallenges0346       map[string]model.ValidationChallenge0346 `json:"validationChallenges0346"`
	ValidationRevocations0346      map[string]bool                          `json:"validationRevocations0346"`
	ValidationPolicies             map[string]model.ProjectValidationPolicy `json:"validationPolicies"`
	Files                          []model.FileObject                       `json:"files"`
	Users                          []model.User                             `json:"users"`
	Identities                     []model.AuthIdentity                     `json:"identities"`
	ProviderCredentials            []model.ProviderCredential               `json:"providerCredentials"`
	MinecraftProfiles              []model.MinecraftProfile                 `json:"minecraftProfiles"`
	MinecraftSessions              []model.MinecraftSession                 `json:"minecraftSessions"`
	MinecraftJoins                 []model.MinecraftJoin                    `json:"minecraftJoins"`
	TrustedDevices                 []model.TrustedDevice                    `json:"trustedDevices"`
	DeviceChallenges               []model.DeviceChallenge                  `json:"deviceChallenges"`
	HardwareEvidence               []model.DeviceHardwareEvidence           `json:"hardwareEvidence"`
	MeasuredBoot0315               []model.MeasuredBootEvidence0315         `json:"measuredBoot0315"`
	Roles                          []model.Role                             `json:"roles"`
	Audit                          []model.AuditEvent                       `json:"audit"`
	Telemetry                      []model.TelemetryEvent                   `json:"telemetry"`
	Crashes                        []model.CrashReport                      `json:"crashes"`
	Extensions                     []model.Extension                        `json:"extensions"`
	ExtensionVersions              []model.ExtensionVersion                 `json:"extensionVersions"`
	ExtensionInstalls              []model.ExtensionInstall                 `json:"extensionInstalls"`
	ExtensionRegistryPublishers    []model.ExtensionRegistryPublisher       `json:"extensionRegistryPublishers"`
	ExtensionRegistryKeys          []model.ExtensionRegistryPublisherKey    `json:"extensionRegistryKeys"`
	ExtensionRegistryVersions      []model.ExtensionRegistryVersion         `json:"extensionRegistryVersions"`
	ExtensionInstallRevisions      []model.ExtensionInstallRevision         `json:"extensionInstallRevisions"`
	ExtensionEvents                []model.ExtensionEvent                   `json:"extensionEvents"`
	ExtensionEventSubscriptions    []model.ExtensionEventSubscription       `json:"extensionEventSubscriptions"`
	ExtensionEventDeliveries       []model.ExtensionEventDelivery           `json:"extensionEventDeliveries"`
	ExtensionEventDeadLetters      []model.ExtensionEventDeadLetter         `json:"extensionEventDeadLetters"`
	ExtensionPermissionGrants      []model.ExtensionPermissionGrant         `json:"extensionPermissionGrants"`
	ExtensionSecrets               []model.ExtensionSecret                  `json:"extensionSecrets"`
	ExtensionUpdatePins            []model.ExtensionUpdatePin               `json:"extensionUpdatePins"`
	ExtensionUpdateTransactions    []model.ExtensionUpdateTransaction       `json:"extensionUpdateTransactions"`
	ExtensionUpdateLeases          map[string]extensionUpdateLease02011     `json:"extensionUpdateLeases"`
	ExtensionTrustPolicy           model.ExtensionTrustPolicy               `json:"extensionTrustPolicy"`
	ExtensionQuarantine            []model.ExtensionQuarantineEntry         `json:"extensionQuarantine"`
	ExtensionEmergencyDisables     []model.ExtensionEmergencyDisable        `json:"extensionEmergencyDisables"`
	NextExtensionInstallRevisionID int64                                    `json:"nextExtensionInstallRevisionID"`
	NextExtensionEventSequence     int64                                    `json:"nextExtensionEventSequence"`
	NextExtensionSubscriptionID    int64                                    `json:"nextExtensionSubscriptionID"`
	NextExtensionDeliveryID        int64                                    `json:"nextExtensionDeliveryID"`
	NextExtensionDeadLetterID      int64                                    `json:"nextExtensionDeadLetterID"`
}

func snapshotSQLiteHTTP0372(r *MemoryRepository) sqliteHTTPState0372 {
	return sqliteHTTPState0372{
		ManagedProviders:               r.managedProviders,
		HwidObservations:               r.hwidObservations,
		HwidAppeals:                    r.hwidAppeals,
		ProtectionBans:                 r.protectionBans,
		BuildWorkspaces:                r.buildWorkspaces,
		OfficialProviderHistory:        r.officialProviderHistory,
		OperationalConfigRevisions:     r.operationalConfigRevisions,
		ReleaseDrafts:                  r.releaseDrafts,
		ChannelHeads:                   r.channelHeads,
		DurableJobs:                    r.durableJobs,
		DurableOpAttempts:              r.durableOpAttempts,
		DurableJobKeys:                 r.durableJobKeys,
		DurableScopeLeases:             r.durableScopeLeases,
		DurableOutbox:                  r.durableOutbox,
		DurableNonces:                  r.durableNonces,
		IdempotencyDigests:             r.idempotencyDigests,
		Projects:                       r.projects,
		ProfileHistory:                 r.profileHistory,
		Profiles:                       r.profiles,
		Channels:                       r.channels,
		Releases:                       r.releases,
		IntegrityChecks:                r.integrityChecks,
		RuntimeValidations:             r.runtimeValidations,
		StagedRuntimeRuns0342:          r.stagedRuntimeRuns0342,
		ValidationAttestations0345:     r.validationAttestations0345,
		ValidationAttempts03412:        r.validationAttempts03412,
		ValidationChallenges0346:       r.validationChallenges0346,
		ValidationRevocations0346:      r.validationRevocations0346,
		ValidationPolicies:             r.validationPolicies,
		Files:                          r.files,
		Users:                          r.users,
		Identities:                     r.identities,
		ProviderCredentials:            r.providerCredentials,
		MinecraftProfiles:              r.minecraftProfiles,
		MinecraftSessions:              r.minecraftSessions,
		MinecraftJoins:                 r.minecraftJoins,
		TrustedDevices:                 r.trustedDevices,
		DeviceChallenges:               r.deviceChallenges,
		HardwareEvidence:               r.hardwareEvidence,
		MeasuredBoot0315:               r.measuredBoot0315,
		Roles:                          r.roles,
		Audit:                          r.audit,
		Telemetry:                      r.telemetry,
		Crashes:                        r.crashes,
		Extensions:                     r.extensions,
		ExtensionVersions:              r.extensionVersions,
		ExtensionInstalls:              r.extensionInstalls,
		ExtensionRegistryPublishers:    r.extensionRegistryPublishers,
		ExtensionRegistryKeys:          r.extensionRegistryKeys,
		ExtensionRegistryVersions:      r.extensionRegistryVersions,
		ExtensionInstallRevisions:      r.extensionInstallRevisions,
		ExtensionEvents:                r.extensionEvents,
		ExtensionEventSubscriptions:    r.extensionEventSubscriptions,
		ExtensionEventDeliveries:       r.extensionEventDeliveries,
		ExtensionEventDeadLetters:      r.extensionEventDeadLetters,
		ExtensionPermissionGrants:      r.extensionPermissionGrants,
		ExtensionSecrets:               r.extensionSecrets,
		ExtensionUpdatePins:            r.extensionUpdatePins,
		ExtensionUpdateTransactions:    r.extensionUpdateTransactions,
		ExtensionUpdateLeases:          r.extensionUpdateLeases,
		ExtensionTrustPolicy:           r.extensionTrustPolicy,
		ExtensionQuarantine:            r.extensionQuarantine,
		ExtensionEmergencyDisables:     r.extensionEmergencyDisables,
		NextExtensionInstallRevisionID: r.nextExtensionInstallRevisionID,
		NextExtensionEventSequence:     r.nextExtensionEventSequence,
		NextExtensionSubscriptionID:    r.nextExtensionSubscriptionID,
		NextExtensionDeliveryID:        r.nextExtensionDeliveryID,
		NextExtensionDeadLetterID:      r.nextExtensionDeadLetterID,
	}
}

func restoreSQLiteHTTP0372(r *MemoryRepository, s sqliteHTTPState0372) {
	r.managedProviders = s.ManagedProviders
	r.hwidObservations = s.HwidObservations
	r.hwidAppeals = s.HwidAppeals
	r.protectionBans = s.ProtectionBans
	r.buildWorkspaces = s.BuildWorkspaces
	r.officialProviderHistory = s.OfficialProviderHistory
	r.operationalConfigRevisions = s.OperationalConfigRevisions
	r.releaseDrafts = s.ReleaseDrafts
	r.channelHeads = s.ChannelHeads
	r.durableJobs = s.DurableJobs
	r.durableOpAttempts = s.DurableOpAttempts
	r.durableJobKeys = s.DurableJobKeys
	r.durableScopeLeases = s.DurableScopeLeases
	r.durableOutbox = s.DurableOutbox
	r.durableNonces = s.DurableNonces
	r.idempotencyDigests = s.IdempotencyDigests
	r.projects = s.Projects
	r.profileHistory = s.ProfileHistory
	r.profiles = s.Profiles
	r.channels = s.Channels
	r.releases = s.Releases
	r.integrityChecks = s.IntegrityChecks
	r.runtimeValidations = s.RuntimeValidations
	r.stagedRuntimeRuns0342 = s.StagedRuntimeRuns0342
	r.validationAttestations0345 = s.ValidationAttestations0345
	r.validationAttempts03412 = s.ValidationAttempts03412
	r.validationChallenges0346 = s.ValidationChallenges0346
	r.validationRevocations0346 = s.ValidationRevocations0346
	r.validationPolicies = s.ValidationPolicies
	r.files = s.Files
	r.users = s.Users
	r.identities = s.Identities
	r.providerCredentials = s.ProviderCredentials
	r.minecraftProfiles = s.MinecraftProfiles
	r.minecraftSessions = s.MinecraftSessions
	r.minecraftJoins = s.MinecraftJoins
	r.trustedDevices = s.TrustedDevices
	r.deviceChallenges = s.DeviceChallenges
	r.hardwareEvidence = s.HardwareEvidence
	r.measuredBoot0315 = s.MeasuredBoot0315
	r.roles = s.Roles
	r.audit = s.Audit
	r.telemetry = s.Telemetry
	r.crashes = s.Crashes
	r.extensions = s.Extensions
	r.extensionVersions = s.ExtensionVersions
	r.extensionInstalls = s.ExtensionInstalls
	r.extensionRegistryPublishers = s.ExtensionRegistryPublishers
	r.extensionRegistryKeys = s.ExtensionRegistryKeys
	r.extensionRegistryVersions = s.ExtensionRegistryVersions
	r.extensionInstallRevisions = s.ExtensionInstallRevisions
	r.extensionEvents = s.ExtensionEvents
	r.extensionEventSubscriptions = s.ExtensionEventSubscriptions
	r.extensionEventDeliveries = s.ExtensionEventDeliveries
	r.extensionEventDeadLetters = s.ExtensionEventDeadLetters
	r.extensionPermissionGrants = s.ExtensionPermissionGrants
	r.extensionSecrets = s.ExtensionSecrets
	r.extensionUpdatePins = s.ExtensionUpdatePins
	r.extensionUpdateTransactions = s.ExtensionUpdateTransactions
	r.extensionUpdateLeases = s.ExtensionUpdateLeases
	r.extensionTrustPolicy = s.ExtensionTrustPolicy
	r.extensionQuarantine = s.ExtensionQuarantine
	r.extensionEmergencyDisables = s.ExtensionEmergencyDisables
	r.nextExtensionInstallRevisionID = s.NextExtensionInstallRevisionID
	r.nextExtensionEventSequence = s.NextExtensionEventSequence
	r.nextExtensionSubscriptionID = s.NextExtensionSubscriptionID
	r.nextExtensionDeliveryID = s.NextExtensionDeliveryID
	r.nextExtensionDeadLetterID = s.NextExtensionDeadLetterID
}
