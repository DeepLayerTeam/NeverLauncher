package repository

// These fields are deliberately excluded from public JSON responses. The
// generic SQLite HTTP snapshot must preserve them nevertheless: losing a
// password verifier, device public key, refresh-token ciphertext or extension
// secret across restart would break authentication and extension execution.
// The parallel arrays follow the exact order of the corresponding snapshot
// slices; their size is checked before restoration and a mismatch fails closed.
type sqliteHTTPPrivate0373 struct {
	PasswordHashes          []string                           `json:"passwordHashes"`
	ProviderRefresh         []string                           `json:"providerRefresh"`
	DevicePublicKeys        []string                           `json:"devicePublicKeys"`
	DeviceChallenges        []string                           `json:"deviceChallenges"`
	MinecraftSessions       []string                           `json:"minecraftSessions"`
	MinecraftJoinUsernames  []string                           `json:"minecraftJoinUsernames"`
	HardwareEvidence        []sqliteHardwarePrivate0373        `json:"hardwareEvidence"`
	MeasuredBoot            []sqliteMeasuredPrivate0373        `json:"measuredBoot"`
	ExtensionSecrets        []sqliteExtensionSecretPrivate0373 `json:"extensionSecrets"`
	ExtensionDeliveryTokens []string                           `json:"extensionDeliveryTokens"`
}
type sqliteHardwarePrivate0373 struct {
	UserID      string `json:"userId"`
	SessionID   string `json:"sessionId"`
	ChallengeID string `json:"challengeId"`
}
type sqliteMeasuredPrivate0373 struct {
	UserID          string `json:"userId"`
	SessionID       string `json:"sessionId"`
	KeyFingerprint  string `json:"keyFingerprint"`
	RootFingerprint string `json:"rootFingerprint"`
	AKFingerprint   string `json:"akFingerprint"`
	ChallengeID     string `json:"challengeId"`
}
type sqliteExtensionSecretPrivate0373 struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

func snapshotPrivateSQLite0373(r *MemoryRepository) sqliteHTTPPrivate0373 {
	out := sqliteHTTPPrivate0373{}
	for _, v := range r.users {
		out.PasswordHashes = append(out.PasswordHashes, v.PasswordHash)
	}
	for _, v := range r.providerCredentials {
		out.ProviderRefresh = append(out.ProviderRefresh, v.EncryptedRefreshToken)
	}
	for _, v := range r.trustedDevices {
		out.DevicePublicKeys = append(out.DevicePublicKeys, v.PublicKey)
	}
	for _, v := range r.deviceChallenges {
		out.DeviceChallenges = append(out.DeviceChallenges, v.ChallengeHash)
	}
	for _, v := range r.minecraftSessions {
		out.MinecraftSessions = append(out.MinecraftSessions, v.AccessTokenHash)
	}
	for _, v := range r.minecraftJoins {
		out.MinecraftJoinUsernames = append(out.MinecraftJoinUsernames, v.UsernameNormalized)
	}
	for _, v := range r.hardwareEvidence {
		out.HardwareEvidence = append(out.HardwareEvidence, sqliteHardwarePrivate0373{v.UserID, v.SessionID, v.ChallengeID})
	}
	for _, v := range r.measuredBoot0315 {
		out.MeasuredBoot = append(out.MeasuredBoot, sqliteMeasuredPrivate0373{v.UserID, v.SessionID, v.KeyFingerprint, v.RootFingerprint, v.AKFingerprint, v.ChallengeID})
	}
	for _, v := range r.extensionSecrets {
		out.ExtensionSecrets = append(out.ExtensionSecrets, sqliteExtensionSecretPrivate0373{v.Ciphertext, v.Nonce})
	}
	for _, v := range r.extensionEventDeliveries {
		out.ExtensionDeliveryTokens = append(out.ExtensionDeliveryTokens, v.LeaseToken)
	}
	return out
}
func restorePrivateSQLite0373(r *MemoryRepository, p sqliteHTTPPrivate0373) {
	for i, v := range p.PasswordHashes {
		r.users[i].PasswordHash = v
	}
	for i, v := range p.ProviderRefresh {
		r.providerCredentials[i].EncryptedRefreshToken = v
	}
	for i, v := range p.DevicePublicKeys {
		r.trustedDevices[i].PublicKey = v
	}
	for i, v := range p.DeviceChallenges {
		r.deviceChallenges[i].ChallengeHash = v
	}
	for i, v := range p.MinecraftSessions {
		r.minecraftSessions[i].AccessTokenHash = v
	}
	for i, v := range p.MinecraftJoinUsernames {
		r.minecraftJoins[i].UsernameNormalized = v
	}
	for i, v := range p.HardwareEvidence {
		r.hardwareEvidence[i].UserID = v.UserID
		r.hardwareEvidence[i].SessionID = v.SessionID
		r.hardwareEvidence[i].ChallengeID = v.ChallengeID
	}
	for i, v := range p.MeasuredBoot {
		r.measuredBoot0315[i].UserID = v.UserID
		r.measuredBoot0315[i].SessionID = v.SessionID
		r.measuredBoot0315[i].KeyFingerprint = v.KeyFingerprint
		r.measuredBoot0315[i].RootFingerprint = v.RootFingerprint
		r.measuredBoot0315[i].AKFingerprint = v.AKFingerprint
		r.measuredBoot0315[i].ChallengeID = v.ChallengeID
	}
	for i, v := range p.ExtensionSecrets {
		r.extensionSecrets[i].Ciphertext = v.Ciphertext
		r.extensionSecrets[i].Nonce = v.Nonce
	}
	for i, v := range p.ExtensionDeliveryTokens {
		r.extensionEventDeliveries[i].LeaseToken = v
	}
}
func validPrivateSQLite0373(s sqliteHTTPState0372) bool {
	p := s.Private0373
	if len(p.PasswordHashes) != 0 && len(p.PasswordHashes) != len(s.Users) {
		return false
	}
	if len(p.ProviderRefresh) != 0 && len(p.ProviderRefresh) != len(s.ProviderCredentials) {
		return false
	}
	if len(p.DevicePublicKeys) != 0 && len(p.DevicePublicKeys) != len(s.TrustedDevices) {
		return false
	}
	if len(p.DeviceChallenges) != 0 && len(p.DeviceChallenges) != len(s.DeviceChallenges) {
		return false
	}
	if len(p.MinecraftSessions) != 0 && len(p.MinecraftSessions) != len(s.MinecraftSessions) {
		return false
	}
	if len(p.MinecraftJoinUsernames) != 0 && len(p.MinecraftJoinUsernames) != len(s.MinecraftJoins) {
		return false
	}
	if len(p.HardwareEvidence) != 0 && len(p.HardwareEvidence) != len(s.HardwareEvidence) {
		return false
	}
	if len(p.MeasuredBoot) != 0 && len(p.MeasuredBoot) != len(s.MeasuredBoot0315) {
		return false
	}
	if len(p.ExtensionSecrets) != 0 && len(p.ExtensionSecrets) != len(s.ExtensionSecrets) {
		return false
	}
	if len(p.ExtensionDeliveryTokens) != 0 && len(p.ExtensionDeliveryTokens) != len(s.ExtensionEventDeliveries) {
		return false
	}
	return true
}
