package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The scoped overview is a server-side security boundary, not just an Admin filter.
func TestServerBridgeOperations0219ProjectIsolation(t *testing.T) {
	h := testServer(t)
	owner := loginAdmin(t, h)

	created := request0211(t, h, http.MethodPost, "/api/v1/admin/projects", owner, `{"id":"bridge-other-0219","name":"Bridge Other","defaultChannel":"stable"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create project: %d %s", created.Code, created.Body.String())
	}
	a := newTestBridgeNodeIdentity0142(t)
	b := newTestBridgeNodeIdentity0142(t)
	if res := registerTestBridgeNode0142(t, h, owner, "bridge-home-0219", "Home", "paper", "demo-project", "vanilla", a); res.Code != http.StatusCreated {
		t.Fatalf("register home: %d %s", res.Code, res.Body.String())
	}
	if res := registerTestBridgeNode0142(t, h, owner, "bridge-away-0219", "Away", "paper", "bridge-other-0219", "", b); res.Code != http.StatusCreated {
		t.Fatalf("register away: %d %s", res.Code, res.Body.String())
	}
	owner, _ = registerTestPasskey117(t, h, owner)
	user := request0211(t, h, http.MethodPost, "/api/v1/admin/users", owner, `{"email":"bridge-operator-0219@example.test","displayName":"Bridge Operator","roleId":"player","password":"bridge-password-0219","projectRoles":{"demo-project":"operator"}}`)
	if user.Code != http.StatusCreated {
		t.Fatalf("create operator: %d %s", user.Code, user.Body.String())
	}
	operator := loginUser0211(t, h, "bridge-operator-0219@example.test", "bridge-password-0219")

	own := request0211(t, h, http.MethodGet, "/api/v1/server-bridge/projects/demo-project/overview", operator, "")
	if own.Code != http.StatusOK {
		t.Fatalf("scoped overview: %d %s", own.Code, own.Body.String())
	}
	var snapshot struct {
		Data struct {
			Nodes   []struct{ ID, ProjectID string } `json:"nodes"`
			Metrics struct {
				NodesTotal int `json:"nodesTotal"`
			} `json:"metrics"`
		} `json:"data"`
	}
	if err := json.Unmarshal(own.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Data.Nodes) != 1 || snapshot.Data.Nodes[0].ID != "bridge-home-0219" || snapshot.Data.Metrics.NodesTotal != 1 {
		t.Fatalf("cross-project node disclosed: %s", own.Body.String())
	}
	other := request0211(t, h, http.MethodGet, "/api/v1/server-bridge/projects/bridge-other-0219/overview", operator, "")
	if other.Code != http.StatusForbidden {
		t.Fatalf("other project overview returned %d: %s", other.Code, other.Body.String())
	}
	global := request0211(t, h, http.MethodGet, "/api/v1/server-bridge/overview", operator, "")
	if global.Code != http.StatusForbidden {
		t.Fatalf("operator reached global overview: %d: %s", global.Code, global.Body.String())
	}
	readOtherCommand := request0211(t, h, http.MethodGet, "/api/v1/server-bridge/servers/bridge-away-0219/control/hidden", operator, "")
	if readOtherCommand.Code != http.StatusNotFound {
		t.Fatalf("operator disclosed other server existence: %d %s", readOtherCommand.Code, readOtherCommand.Body.String())
	}
}
