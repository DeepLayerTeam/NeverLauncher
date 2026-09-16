#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
API = ROOT / "services" / "api"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
OUT = pathlib.Path(os.environ.get("NEVERLAUNCHER_FEDERATION_E2E_REPORT", ROOT / "dist" / "reports" / "federation-e2e.json"))

CASES = [
    {
        "id": "canonical-session-matrix",
        "package": "./internal/httpapi",
        "tests": [
            "TestFederationE2E01110CanonicalSessionMatrix",
        ],
        "coverage": ["local", "sql", "http", "oidc", "microsoft", "passkey", "refresh", "revoke", "minecraft-session"],
    },
    {
        "id": "local",
        "package": "./internal/httpapi",
        "tests": [
            "TestLocalConnector112Conformance",
            "TestAuthSession111RefreshReplayRevokesFamily",
            "TestMinecraftAuth119NeverSessionExchangeJoinAndParentRevoke",
        ],
        "coverage": ["login", "refresh", "revoke", "minecraft-join"],
    },
    {
        "id": "sql",
        "package": "./internal/sqlconnector",
        "tests": [
            "TestAuthenticatePasswordQueriesReadOnlyAndMapsIdentity",
            "TestAuthenticatePasswordRejectsDisabledIdentity",
            "TestBuildQueriesUsesDriverPlaceholders",
            "TestTLSPolicyRejectsPlaintextFallback",
        ],
        "coverage": ["login", "mapping", "read-only", "tls"],
    },
    {
        "id": "http",
        "package": "./internal/httpconnector",
        "tests": [
            "TestHTTPConnectorProductionFlow",
            "TestHTTPConnectorRejectsBadSignatureAndSubjectChange",
            "TestResponseReplayAndTimestampWindowAreRejected",
            "TestSSRFSafeDialerRejectsPrivateByDefault",
        ],
        "coverage": ["login", "refresh", "revoke", "ssrf", "replay"],
    },
    {
        "id": "oidc",
        "package": "./internal/oidcconnector",
        "tests": [
            "TestOIDCConnectorAuthorizationCodePKCEAndIDTokenValidation",
            "TestJWTRejectsAudienceAndIssuerMismatch",
            "TestOIDCNormalizeRejectsUnsafeConfiguration",
        ],
        "coverage": ["browser-login", "pkce", "jwks", "issuer", "audience"],
    },
    {
        "id": "microsoft",
        "package": "./internal/microsoftconnector",
        "tests": [
            "TestMicrosoftConnectorAuthorizationCodePKCEMultitenantAndRefresh",
            "TestMicrosoftIssuerPolicyRejectsTenantAndSigningKeyConfusion",
        ],
        "coverage": ["browser-login", "refresh", "logout", "tenant-isolation"],
    },
    {
        "id": "passkey",
        "package": "./internal/httpapi",
        "tests": [
            "TestPasskeyRegistrationAndPasswordlessLogin117",
            "TestPhishingResistantPolicyBlocksSessionUntilPasskey117",
        ],
        "coverage": ["register", "passwordless-login", "mfa-continuation", "session"],
    },
    {
        "id": "canonical-federation",
        "package": "./internal/federation",
        "tests": [
            "TestAuthenticatePasswordResolvesCanonicalUser",
            "TestAuthenticatePasswordJITProvisionsCanonicalUser",
            "TestJITProvisioningDoesNotAutoLinkMatchingEmail",
            "TestLinkAuthenticatedIdentityRejectsReassignment",
        ],
        "coverage": ["canonical-user", "jit", "explicit-link", "conflict"],
    },
    {
        "id": "release-linking-status",
        "package": "./internal/httpapi",
        "tests": [
            "TestGenericBrowserProviderExplicitLink0120",
            "TestFederationStatus0120ReportsProviderHealth",
        ],
        "coverage": ["provider-agnostic-explicit-link", "runtime-provider-health"],
    },
    {
        "id": "minecraft-after-federation",
        "package": "./internal/httpapi",
        "tests": [
            "TestMinecraftAuth119YggdrasilPasswordUsesFederationCore",
            "TestMinecraftAuth119PlayerRoleCanExchangeSession",
            "TestMinecraftAuth119RefreshConsumesOldToken",
        ],
        "coverage": ["federation-to-minecraft", "player-role", "token-rotation"],
    },
    {
        "id": "failure-matrix",
        "package": "./internal/webauthn",
        "tests": [
            "TestAssertionRejectsReplayAndWrongOrigin",
        ],
        "coverage": ["wrong-origin", "challenge-replay"],
    },
]


def run_case(case: dict) -> dict:
    regex = "^(?:" + "|".join(case["tests"]) + ")$"
    cmd = ["go", "test", "-tags", "neverlauncher_nopgx", case["package"], "-run", regex, "-count=1"]
    started = time.time()
    proc = subprocess.run(cmd, cwd=API, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    result = dict(case)
    result["status"] = "passed" if proc.returncode == 0 else "failed"
    result["durationMs"] = int((time.time() - started) * 1000)
    result["command"] = " ".join(cmd)
    result["output"] = proc.stdout[-12000:]
    return result


def main() -> int:
    results = []
    failed = False
    for case in CASES:
        print(f"[federation-e2e] {case['id']} ...", flush=True)
        result = run_case(case)
        results.append(result)
        if result["status"] != "passed":
            failed = True
            print(result["output"], file=sys.stderr)
        else:
            print(f"[federation-e2e] {case['id']} PASS ({result['durationMs']} ms)")
    report = {
        "schemaVersion": "1",
        "toolVersion": VERSION,
        "status": "failed" if failed else "passed",
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "matrix": results,
        "requiredProviders": ["local", "sql", "http", "oidc", "microsoft", "passkey"],
        "releaseGate": True,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[federation-e2e] report: {OUT}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
