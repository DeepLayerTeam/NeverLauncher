package httpapi

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

const guardSessionBatchSize0507 = 32

func (s Server) guardBoundStore0507() (repository.GuardBoundSessionStore0507, error) {
	if s.State == nil || s.State.ServerBridge == nil {
		return nil, errors.New("Недоступно: «серверный компонент сеансов Guard»")
	}
	store, ok := s.State.ServerBridge.backendV2().(repository.GuardBoundSessionStore0507)
	if !ok {
		return nil, errors.New("Для сессия Guard требуется «durable PostgreSQL backend»")
	}
	return store, nil
}

// Непроверенные поля запроса нельзя записывать в сохраняемую привязку Guard.
// Сначала вызывающий обязан погасить непрерывную аттестацию, подписанную
// устройством, и одноразовый подписанный устройством challenge точного плана
// компонентов.
func createGuardBoundSession0507(join bridgeJoinRecord, verifiedPlan *verifiedPlanEvidence02412, verified model.DeviceChallenge) (repository.GuardBoundSession0507, error) {
	if verifiedPlan == nil || verified.ID == "" || join.SessionCorrelationID == "" {
		return repository.GuardBoundSession0507{}, errors.New("Требуется: «verified build and Guard evidence»")
	}
	m := verified.Metadata
	major, err := strconv.Atoi(metadataString0121(m, "javaMajor"))
	if err != nil || major < 1 {
		return repository.GuardBoundSession0507{}, errors.New("Некорректное значение: Guard основная версия Java")
	}
	pid, err := strconv.ParseInt(metadataString0121(m, "runtimePid"), 10, 64)
	if err != nil || pid < 1 {
		return repository.GuardBoundSession0507{}, errors.New("Некорректное значение: Guard процесс ID")
	}
	b := repository.GuardBoundSession0507{
		CorrelationID: join.SessionCorrelationID, JoinID: join.ID, UserID: join.UserID, SessionID: join.SessionID,
		MinecraftSessionID: join.MinecraftSessionID, TrustedDeviceID: join.TrustedDeviceID, BindingEpoch: join.BindingEpoch,
		DeviceKeyFingerprint: metadataString0121(m, "deviceKeyFingerprint"), ServerID: join.ServerID,
		ProjectID: join.ProjectID, ProfileID: join.ProfileID, Channel: join.Channel, Username: join.Username, PlayerUUID: join.UUID, IdentityRealm: join.IdentityRealm,
		PlanSHA256: verifiedPlan.PlanSHA256, CatalogSHA256: verifiedPlan.CatalogDigest, ReleaseSignature: verifiedPlan.ReleaseSignature,
		GuardAttestationSHA256: verifiedPlan.GuardAttestationSHA256, GuardEvidenceSHA256: metadataString0121(m, "continuousEvidenceSha256"),
		GuardSHA256: metadataString0121(m, "guardSha256"), LauncherSHA256: metadataString0121(m, "launcherSha256"),
		LauncherVersion: metadataString0121(m, "launcherVersion"), RuntimePolicySHA256: metadataString0121(m, "runtimePolicySha256"),
		ModuleSetSHA256: metadataString0121(m, "moduleSetSha256"), CodeSetSHA256: metadataString0121(m, "codeSetSha256"),
		HookSetSHA256: metadataString0121(m, "hookSetSha256"), JVMStateSHA256: metadataString0121(m, "jvmStateSha256"),
		JavaMajor: major, GuardPID: pid, IssuedAt: verified.CreatedAt.UTC(),
	}
	if verifiedPlan.UserID != b.UserID || verifiedPlan.SessionID != b.SessionID || verifiedPlan.DeviceID != b.TrustedDeviceID || verifiedPlan.BindingEpoch != b.BindingEpoch ||
		verifiedPlan.ServerID != b.ServerID || verifiedPlan.ProjectID != b.ProjectID || verifiedPlan.ProfileID != b.ProfileID || verifiedPlan.Channel != b.Channel ||
		verifiedPlan.GuardAttestationSHA256 != metadataString0121(m, "attestationSha256") ||
		metadataString0121(m, "sessionId") != b.SessionID || metadataString0121(m, "bindingEpoch") != strconv.FormatInt(b.BindingEpoch, 10) ||
		metadataString0121(m, "minecraftSessionId") != b.MinecraftSessionID && b.IdentityRealm != "official" {
		return repository.GuardBoundSession0507{}, errors.New("Несовпадение: «Guard / component plan session binding»")
	}
	if !isSHA256Hex0134(b.CorrelationID) || !isSHA256Hex0134(b.PlanSHA256) || !isSHA256Hex0134(b.CatalogSHA256) ||
		!isHexLength02412(b.ReleaseSignature, 128) || !isSHA256Hex0134(b.GuardAttestationSHA256) || !isSHA256Hex0134(b.GuardEvidenceSHA256) ||
		!isSHA256Hex0134(b.DeviceKeyFingerprint) || !isSHA256Hex0134(b.GuardSHA256) || !isSHA256Hex0134(b.LauncherSHA256) ||
		!isSHA256Hex0134(b.RuntimePolicySHA256) || !isSHA256Hex0134(b.ModuleSetSHA256) || !isSHA256Hex0134(b.CodeSetSHA256) ||
		!isSHA256Hex0134(b.HookSetSHA256) || !isSHA256Hex0134(b.JVMStateSHA256) {
		return repository.GuardBoundSession0507{}, errors.New("Неправильный формат: сеанс Guard дайджест")
	}
	if join.IdentityRealm != "local" && join.IdentityRealm != "official" {
		return repository.GuardBoundSession0507{}, errors.New("Неизвестное значение: «Minecraft identity realm»")
	}
	return b, nil
}

func (s Server) storeGuardBoundJoin0507(r *http.Request, join bridgeJoinRecord, plan *verifiedPlanEvidence02412, ticket model.DeviceChallenge) error {
	store, err := s.guardBoundStore0507()
	if err != nil {
		return err
	}
	binding, err := createGuardBoundSession0507(join, plan, ticket)
	if err != nil {
		return err
	}
	return store.SaveGuardBoundSession0507(r.Context(), binding)
}

func equalGuardBinding0507(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Проверяйте на авторитетном пути погашения ServerBridge ДО использования
// одноразового билета. Передача может вести на другой узел, но корреляция,
// личность, проект и подписанный ИСХОДНЫЙ план должны совпасть.
func (s Server) requireGuardBoundJoin0507(r *http.Request, join bridgeJoinRecord, handoff bool) error {
	if !planPolicyRequired02412() {
		return nil
	}
	store, err := s.guardBoundStore0507()
	if err != nil {
		return err
	}
	b, err := store.GetGuardBoundSession0507(r.Context(), join.SessionCorrelationID)
	if err != nil {
		return errors.New("Не найдено: «подписанная привязка сеанса Guard»")
	}
	if b.UserID != join.UserID || b.SessionID != join.SessionID || b.MinecraftSessionID != join.MinecraftSessionID ||
		b.TrustedDeviceID != join.TrustedDeviceID || b.BindingEpoch != join.BindingEpoch || b.ProjectID != join.ProjectID ||
		b.ProfileID != join.ProfileID || b.Channel != join.Channel || b.PlayerUUID != join.UUID ||
		!strings.EqualFold(b.Username, join.Username) || b.IdentityRealm != join.IdentityRealm ||
		(!handoff && (b.JoinID != join.ID || b.ServerID != join.ServerID)) {
		return errors.New("Несовпадение: «привязка сеанса Guard к учётной записи, серверу и сборке»")
	}
	// Передача через прокси меняет целевой сервер, но не должна расширять
	// разрешённое множество серверов подписанной сборки. Требуйте явного допуска
	// строго того же плана для новой цели, а не только для прежней.
	if handoff && join.ServerID != b.ServerID {
		policy, err := loadPlanPolicy02412(time.Now().UTC())
		if err != nil || !planMatches02412(policy, join.ServerID, b.ProjectID, b.ProfileID, b.Channel, b.ReleaseSignature, b.CatalogSHA256, b.PlanSHA256) {
			return errors.New("Целевой узел передачи сессии Guard не подписан для этой сборки")
		}
	}
	return s.verifyGuardBoundState0507(r, b)
}

// Используйте текущее авторитетное состояние: устройство, активный сеанс, подписанный
// релиз и точный подписанный план. Никогда не считайте heartbeat игрового сервера
// новым доказательством памяти клиента или инструментирования. Сравнивайте строку из
// действующего авторитетного PostgreSQL-хранилища сеансов с точным одноразовым
// подписанным допуском. Несовпадение требует отзыва, а не фильтрации из SELECT.
func guardBoundLiveMatches0507(b repository.GuardBoundSession0507) bool {
	return b.LiveUserID == b.UserID && b.LiveSessionID == b.SessionID &&
		b.LiveMinecraftSessionID == b.MinecraftSessionID && b.LiveTrustedDeviceID == b.TrustedDeviceID &&
		b.LiveBindingEpoch == b.BindingEpoch && b.LiveProjectID == b.ProjectID && b.LiveProfileID == b.ProfileID &&
		b.LiveChannel == b.Channel && b.LiveUUID == b.PlayerUUID && strings.EqualFold(b.LiveUsername, b.Username)
}

func (s Server) verifyGuardBoundState0507(r *http.Request, b repository.GuardBoundSession0507) error {
	now := time.Now().UTC()
	if b.IssuedAt.IsZero() || b.IssuedAt.After(now.Add(guardAttestationClockSkew0134)) || !isSHA256Hex0134(b.CorrelationID) ||
		b.GuardPID < 1 || b.JavaMajor < 1 {
		return errors.New("guard_binding_invalid")
	}
	_, trust := s.evaluateGameplayTrust0127(r, b.UserID, b.SessionID, b.TrustedDeviceID, b.BindingEpoch, true)
	if !trust.Allowed {
		return fmt.Errorf("guard_session_trust_%s", trust.Reason)
	}
	device, err := s.Repo.GetTrustedDevice(b.UserID, b.TrustedDeviceID)
	if err != nil || device.Status != "active" || device.TrustState != "verified" || !equalGuardBinding0507(device.KeyFingerprint, b.DeviceKeyFingerprint) {
		return errors.New("guard_device_key_revoked")
	}
	state, _ := effectiveDeviceAttestation0124(device, now)
	if state != "verified" {
		return errors.New("guard_device_attestation_expired")
	}
	policies, err := s.guardReleasePolicies0134()
	if err != nil {
		return errors.New("guard_release_unavailable")
	}
	release, ok := policies[b.LauncherVersion]
	if !ok {
		return errors.New("guard_release_revoked")
	}
	accepted, _, err := release.allowsArtifactPair0140(device.Platform, b.GuardSHA256, b.LauncherSHA256)
	if err != nil || !accepted {
		return errors.New("guard_artifact_revoked")
	}
	digest, err := verifyGuardRuntimePolicy0317(release, device.Platform, guardContinuousEvidence01810{
		JavaMajor: uint32(b.JavaMajor), ModuleSetSHA256: b.ModuleSetSHA256,
		CodeSetSHA256: b.CodeSetSHA256, HookSetSHA256: b.HookSetSHA256,
	})
	if err != nil || !equalGuardBinding0507(digest, b.RuntimePolicySHA256) {
		return errors.New("guard_runtime_policy_revoked")
	}
	policy, err := loadPlanPolicy02412(now)
	if err != nil {
		return errors.New("guard_build_policy_unavailable")
	}
	if !planMatches02412(policy, b.ServerID, b.ProjectID, b.ProfileID, b.Channel, b.ReleaseSignature, b.CatalogSHA256, b.PlanSHA256) {
		return errors.New("guard_build_revoked")
	}
	if b.IdentityRealm == "official" {
		store, ok := s.officialLinkStore0268()
		if !ok {
			return errors.New("guard_official_identity_store_unavailable")
		}
		links, err := store.ListOfficialLinks0268(r.Context(), b.UserID)
		if err != nil {
			return errors.New("guard_official_identity_store_unavailable")
		}
		authorized := false
		for _, link := range links {
			if strings.EqualFold(link.MinecraftUUID, b.PlayerUUID) && strings.EqualFold(link.MinecraftName, b.Username) {
				authorized = true
				break
			}
		}
		if !authorized {
			return errors.New("guard_official_identity_unlinked")
		}
	} else if b.IdentityRealm == "local" {
		repo, err := s.minecraftRepo119()
		if err != nil {
			return errors.New("guard_minecraft_repository_unavailable")
		}
		minecraft, err := repo.GetMinecraftSession(b.MinecraftSessionID)
		if err != nil || minecraft.Status != "active" || !minecraft.ExpiresAt.After(now) ||
			minecraft.UserID != b.UserID || minecraft.NeverSessionID != b.SessionID || minecraft.TrustedDeviceID != b.TrustedDeviceID ||
			minecraft.BindingEpoch != b.BindingEpoch || !equalGuardBinding0507(strings.ToLower(minecraft.GuardSHA256), b.GuardSHA256) ||
			!equalGuardBinding0507(strings.ToLower(minecraft.LauncherSHA256), b.LauncherSHA256) || minecraft.LauncherVersion != b.LauncherVersion {
			return errors.New("guard_minecraft_session_invalid")
		}
		if decision := s.evaluateMinecraftIntegrity0135(minecraft); !decision.Allowed {
			return fmt.Errorf("guard_minecraft_%s", decision.Reason)
		}
	} else {
		return errors.New("guard_identity_realm_invalid")
	}
	return nil
}

// Вызывается аутентифицированным ServerBridge heartbeat с защитой от повторов, а не
// HTTP-запросом пользователя. Неуспешная проверка атомарно аннулирует связанный
// сеанс игрока и ставит в очередь команды отключения с привязкой к Runtime.
func (s Server) recheckServerBoundGuard0507(r *http.Request, nodeID string) (int, int, error) {
	if !planPolicyRequired02412() {
		return 0, 0, nil
	}
	store, err := s.guardBoundStore0507()
	if err != nil {
		return 0, 0, err
	}
	now := time.Now().UTC()
	// При включённом контроле Guard отзывайте сеансы игроков, созданные до
	// политики и не имеющие подписанной привязки, а не ожидайте нового входа.
	revoked := 0
	if planPolicyRequired02412() {
		unbound, err := store.ListUnboundGuardPlayerSessions0507(r.Context(), nodeID, guardSessionBatchSize0507)
		if err != nil {
			return 0, 0, err
		}
		for _, correlation := range unbound {
			started := time.Now()
			invalidated, err := store.InvalidateGuardBoundSession0507(r.Context(), correlation, "guard_binding_missing", time.Now().UTC())
			if err != nil {
				return 0, revoked, err
			}
			if invalidated {
				revoked++
				if err := recordGuardShadow05012(s.Version, nodeID, correlation, "revoked", "guard_binding_missing", time.Since(started)); err != nil {
					return 0, revoked, err
				}
			}
		}
	}
	due, err := store.ListDueGuardBoundSessions0507(r.Context(), nodeID, now, guardSessionBatchSize0507)
	if err != nil {
		return 0, 0, err
	}
	checked := 0
	for _, b := range due {
		started := time.Now()
		if err := r.Context().Err(); err != nil {
			return checked, revoked, err
		}
		var reason error
		if !guardBoundLiveMatches0507(b) {
			reason = errors.New("guard_live_session_binding_changed")
		} else {
			reason = s.verifyGuardBoundState0507(r, b)
		}
		if reason != nil {
			invalidated, err := store.InvalidateGuardBoundSession0507(r.Context(), b.CorrelationID, reason.Error(), time.Now().UTC())
			if err != nil {
				return checked, revoked, err
			}
			if invalidated {
				revoked++
				if err := recordGuardShadow05012(s.Version, nodeID, b.CorrelationID, "revoked", reason.Error(), time.Since(started)); err != nil {
					return checked, revoked, err
				}
			}
		} else if err := store.MarkGuardBoundSessionChecked0507(r.Context(), b.CorrelationID, time.Now().UTC()); err != nil {
			return checked, revoked, err
		} else if reason == nil {
			if err := recordGuardShadow05012(s.Version, nodeID, b.CorrelationID, "allowed", "none", time.Since(started)); err != nil {
				return checked, revoked, err
			}
		}
		checked++
	}
	return checked, revoked, nil
}

// Для внутренней проверки без раскрытия хешей Guard и корреляционных токенов.
func guardBoundStatus0507(checked, revoked int) map[string]any {
	return map[string]any{"required": true, "checked": checked, "revoked": revoked, "batchLimit": guardSessionBatchSize0507, "verification": "server-authoritative-recheck"}
}
