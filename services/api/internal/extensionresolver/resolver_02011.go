package extensionresolver

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type Environment struct{ LauncherVersion, APIVersion, OS, Architecture, DefaultChannel string }
type Scope struct{ Scope, ScopeID string }
type Resolver struct {
	Repo repository.Repository
	Env  Environment
}

type requirement struct {
	id, constraint, channel, from string
	optional                      bool
	root                          bool
}
type selection struct {
	item       model.ExtensionRegistryVersion
	channel    string
	requiredBy map[string]struct{}
	optional   bool
	root       bool
}

type state struct{ selected map[string]selection }

func New(repo repository.Repository, env Environment) *Resolver {
	if env.OS == "" {
		env.OS = runtime.GOOS
	}
	if env.Architecture == "" {
		env.Architecture = runtime.GOARCH
	}
	if env.DefaultChannel == "" {
		env.DefaultChannel = "stable"
	}
	if env.APIVersion == "" {
		env.APIVersion = "3.7"
	}
	return &Resolver{Repo: repo, Env: env}
}

func normalizeScope(s Scope) (Scope, error) {
	s.Scope = strings.ToLower(strings.TrimSpace(s.Scope))
	s.ScopeID = strings.TrimSpace(s.ScopeID)
	if s.Scope == "" {
		s.Scope = "global"
	}
	if s.Scope != "global" && s.Scope != "project" {
		return s, errors.New("scope must be global or project")
	}
	if s.Scope == "global" {
		s.ScopeID = ""
	} else if s.ScopeID == "" {
		return s, errors.New("project scope requires scopeId")
	}
	return s, nil
}
func normalizeChannel(ch string) string {
	ch = strings.ToLower(strings.TrimSpace(ch))
	if ch == "" {
		return "stable"
	}
	return ch
}
func allowedChannel(ch string) bool { return ch == "stable" || ch == "beta" || ch == "dev" }
func channelRank(ch string) []string {
	switch ch {
	case "dev":
		return []string{"dev", "beta", "stable"}
	case "beta":
		return []string{"beta", "stable"}
	default:
		return []string{"stable"}
	}
}
func hasChannel(v model.ExtensionRegistryVersion, ch string) bool {
	for _, x := range v.Channels {
		if x == ch {
			return true
		}
	}
	return false
}
func exactConstraint02011(raw string) bool {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "="))
	_, err := ParseVersion(raw)
	return err == nil
}
func conflictsSelected02011(cand model.ExtensionRegistryVersion, selected map[string]selection) bool {
	for id, other := range selected {
		if id == cand.ExtensionID {
			continue
		}
		if conflictMatch(cand.Manifest, id, other.item.Version) || conflictMatch(other.item.Manifest, cand.ExtensionID, cand.Version) {
			return true
		}
	}
	return false
}

func normalizeAPIVersion(v string) (Version, error) {
	v = strings.TrimSpace(v)
	if strings.Count(v, ".") == 1 {
		v += ".0"
	}
	return ParseVersion(v)
}
func compatible(item model.ExtensionRegistryVersion, env Environment) bool {
	if item.YankedAt != nil {
		return false
	}
	lv, e := ParseVersion(env.LauncherVersion)
	if e != nil {
		return false
	}
	c := item.Compatibility
	if c.MinNeverLauncher != "" {
		x, e := ParseVersion(c.MinNeverLauncher)
		if e != nil || Compare(lv, x) < 0 {
			return false
		}
	}
	if c.MaxNeverLauncher != "" {
		x, e := ParseVersion(c.MaxNeverLauncher)
		if e != nil || Compare(lv, x) > 0 {
			return false
		}
	}
	api, e := normalizeAPIVersion(env.APIVersion)
	if e != nil {
		return false
	}
	if c.MinAPI != "" {
		x, e := normalizeAPIVersion(c.MinAPI)
		if e != nil || Compare(api, x) < 0 {
			return false
		}
	}
	if c.MaxAPI != "" {
		x, e := normalizeAPIVersion(c.MaxAPI)
		if e != nil || Compare(api, x) > 0 {
			return false
		}
	}
	if c.MinAPI == "" && c.MaxAPI == "" && strings.TrimSpace(item.Manifest.API) != "" {
		declared, e := normalizeAPIVersion(item.Manifest.API)
		if e != nil || declared.Major != api.Major || declared.Minor != api.Minor {
			return false
		}
	}
	contains := func(xs []string, v string) bool {
		if len(xs) == 0 {
			return true
		}
		for _, x := range xs {
			if strings.EqualFold(x, v) {
				return true
			}
		}
		return false
	}
	return contains(c.SupportedOS, env.OS) && contains(c.SupportedArchitectures, env.Architecture)
}

func cloneState(in state) state {
	out := state{selected: map[string]selection{}}
	for k, v := range in.selected {
		cp := v
		cp.requiredBy = map[string]struct{}{}
		for x := range v.requiredBy {
			cp.requiredBy[x] = struct{}{}
		}
		out.selected[k] = cp
	}
	return out
}

func (r *Resolver) Resolve(ctx context.Context, scope Scope, roots []model.ExtensionUpdateRoot) (model.ExtensionUpdatePlan, error) {
	if r == nil || r.Repo == nil {
		return model.ExtensionUpdatePlan{}, errors.New("extension resolver repository is unavailable")
	}
	var err error
	scope, err = normalizeScope(scope)
	if err != nil {
		return model.ExtensionUpdatePlan{}, err
	}
	if !allowedChannel(normalizeChannel(r.Env.DefaultChannel)) {
		return model.ExtensionUpdatePlan{}, errors.New("default channel must be stable, beta or dev")
	}
	installs, err := r.Repo.ListExtensionInstallStates(ctx, scope.Scope, scope.ScopeID)
	if err != nil {
		return model.ExtensionUpdatePlan{}, err
	}
	installMap := map[string]model.ExtensionInstall{}
	for _, x := range installs {
		if x.CurrentState != model.ExtensionInstallStateAbsent {
			installMap[x.ExtensionID] = x
		}
	}
	if len(roots) == 0 {
		for _, x := range installs {
			if x.CurrentState != model.ExtensionInstallStateAbsent {
				roots = append(roots, model.ExtensionUpdateRoot{ExtensionID: x.ExtensionID, Channel: r.Env.DefaultChannel})
			}
		}
	}
	if len(roots) == 0 {
		return model.ExtensionUpdatePlan{}, errors.New("no installed extensions or update roots")
	}
	pins, err := r.Repo.ListExtensionUpdatePins(ctx, scope.Scope, scope.ScopeID)
	if err != nil {
		return model.ExtensionUpdatePlan{}, err
	}
	pinMap := map[string]string{}
	for _, p := range pins {
		pinMap[p.ExtensionID] = p.Version
	}
	var tasks []requirement
	for _, root := range roots {
		id := strings.ToLower(strings.TrimSpace(root.ExtensionID))
		if id == "" {
			return model.ExtensionUpdatePlan{}, errors.New("update root extensionId is required")
		}
		ch := normalizeChannel(root.Channel)
		if !allowedChannel(ch) {
			return model.ExtensionUpdatePlan{}, fmt.Errorf("unsupported update channel %q", ch)
		}
		c := "*"
		if strings.TrimSpace(root.Version) != "" {
			c = "=" + strings.TrimSpace(root.Version)
		}
		tasks = append(tasks, requirement{id: id, constraint: c, channel: ch, from: "root", root: true})
	}
	all, err := r.Repo.SearchExtensionRegistry(ctx, model.ExtensionRegistrySearch{IncludeYanked: false})
	if err != nil {
		return model.ExtensionUpdatePlan{}, err
	}
	byID := map[string][]model.ExtensionRegistryVersion{}
	for _, v := range all {
		if compatible(v, r.Env) {
			byID[v.ExtensionID] = append(byID[v.ExtensionID], v)
		}
	}
	for id := range byID {
		sort.Slice(byID[id], func(i, j int) bool {
			a, _ := ParseVersion(byID[id][i].Version)
			b, _ := ParseVersion(byID[id][j].Version)
			return Compare(a, b) > 0
		})
	}
	solved, err := r.solve(tasks, state{selected: map[string]selection{}}, byID, pinMap)
	if err != nil {
		return model.ExtensionUpdatePlan{}, err
	}
	if err := r.validateFinalConflicts(ctx, solved.selected, installMap); err != nil {
		return model.ExtensionUpdatePlan{}, err
	}
	order, err := topologicalOrder(solved.selected)
	if err != nil {
		return model.ExtensionUpdatePlan{}, err
	}
	plan := model.ExtensionUpdatePlan{Scope: scope.Scope, ScopeID: scope.ScopeID, LauncherVersion: r.Env.LauncherVersion, APIVersion: r.Env.APIVersion, OS: r.Env.OS, Architecture: r.Env.Architecture, DefaultChannel: normalizeChannel(r.Env.DefaultChannel), ResolvedAt: time.Now().UTC()}
	for _, id := range order {
		sel := solved.selected[id]
		from := ""
		op := "install"
		if x, ok := installMap[id]; ok {
			from = x.CurrentVersion
			if from == sel.item.Version {
				op = "unchanged"
			} else {
				op = "update"
			}
		}
		req := make([]string, 0, len(sel.requiredBy))
		for x := range sel.requiredBy {
			req = append(req, x)
		}
		sort.Strings(req)
		_, pinned := pinMap[id]
		plan.Items = append(plan.Items, model.ExtensionUpdatePlanItem{ExtensionID: id, FromVersion: from, ToVersion: sel.item.Version, PackageIdentity: sel.item.Artifact.PackageIdentity, Operation: op, Channel: sel.channel, RequiredBy: req, Optional: sel.optional, Pinned: pinned})
	}
	return plan, nil
}

func (r *Resolver) solve(tasks []requirement, st state, byID map[string][]model.ExtensionRegistryVersion, pins map[string]string) (state, error) {
	if len(tasks) == 0 {
		return st, nil
	}
	req := tasks[0]
	rest := tasks[1:]
	if existing, ok := st.selected[req.id]; ok {
		if !Matches(existing.item.Version, req.constraint) {
			if req.optional {
				return r.solve(rest, st, byID, pins)
			}
			return state{}, fmt.Errorf("dependency %s selected %s does not satisfy %s required by %s", req.id, existing.item.Version, req.constraint, req.from)
		}
		cp := cloneState(st)
		x := cp.selected[req.id]
		if req.from != "root" {
			x.requiredBy[req.from] = struct{}{}
		}
		x.root = x.root || req.root
		x.optional = x.optional && req.optional
		cp.selected[req.id] = x
		return r.solve(rest, cp, byID, pins)
	}
	constraint, err := ParseConstraint(req.constraint)
	if err != nil {
		return state{}, fmt.Errorf("%s constraint %q: %w", req.id, req.constraint, err)
	}
	candidates := append([]model.ExtensionRegistryVersion(nil), byID[req.id]...)
	var filtered []model.ExtensionRegistryVersion
	pin := pins[req.id]
	if pin != "" || exactConstraint02011(req.constraint) {
		for _, v := range candidates {
			vv, e := ParseVersion(v.Version)
			if e != nil || !constraint.Match(vv) {
				continue
			}
			if pin != "" && v.Version != pin {
				continue
			}
			filtered = append(filtered, v)
		}
	} else {
		channels := channelRank(req.channel)
		seenVersions := map[string]struct{}{}
		for _, channel := range channels {
			for _, v := range candidates {
				vv, e := ParseVersion(v.Version)
				if e != nil || !constraint.Match(vv) || !hasChannel(v, channel) {
					continue
				}
				if _, seen := seenVersions[v.Version]; seen {
					continue
				}
				seenVersions[v.Version] = struct{}{}
				filtered = append(filtered, v)
			}
		}
	}
	if len(filtered) == 0 {
		if req.optional {
			return r.solve(rest, st, byID, pins)
		}
		if pin := pins[req.id]; pin != "" {
			return state{}, fmt.Errorf("pinned extension %s@%s cannot satisfy %s/channel %s/platform compatibility", req.id, pin, req.constraint, req.channel)
		}
		return state{}, fmt.Errorf("no compatible registry version for %s %s in channel %s", req.id, req.constraint, req.channel)
	}
	var last error
	for _, cand := range filtered {
		if conflictsSelected02011(cand, st.selected) {
			last = fmt.Errorf("candidate %s@%s conflicts with selected graph", cand.ExtensionID, cand.Version)
			continue
		}
		cp := cloneState(st)
		rb := map[string]struct{}{}
		if req.from != "root" {
			rb[req.from] = struct{}{}
		}
		cp.selected[req.id] = selection{item: cand, channel: req.channel, requiredBy: rb, optional: req.optional, root: req.root}
		next := append([]requirement(nil), rest...)
		deps := append([]model.ExtensionDependency(nil), cand.Manifest.Dependencies...)
		sort.SliceStable(deps, func(i, j int) bool { return !deps[i].Optional && deps[j].Optional })
		for i := len(deps) - 1; i >= 0; i-- {
			d := deps[i]
			next = append([]requirement{{id: d.ID, constraint: d.Version, channel: req.channel, from: req.id, optional: d.Optional}}, next...)
		}
		got, e := r.solve(next, cp, byID, pins)
		if e == nil {
			return got, nil
		}
		last = e
	}
	if req.optional {
		return r.solve(rest, st, byID, pins)
	}
	if last != nil {
		return state{}, last
	}
	return state{}, fmt.Errorf("unable to resolve %s", req.id)
}

func conflictMatch(m model.ExtensionManifest, otherID, otherVersion string) bool {
	for _, c := range m.Conflicts {
		if c.ID == otherID && Matches(otherVersion, c.Version) {
			return true
		}
	}
	return false
}
func (r *Resolver) validateFinalConflicts(ctx context.Context, selected map[string]selection, installed map[string]model.ExtensionInstall) error {
	finals := map[string]model.ExtensionManifest{}
	versions := map[string]string{}
	for id, s := range selected {
		finals[id] = s.item.Manifest
		versions[id] = s.item.Version
	}
	for id, ins := range installed {
		if _, ok := selected[id]; ok {
			continue
		}
		v, e := r.Repo.GetExtensionVersion(ctx, id, ins.CurrentVersion)
		if e != nil {
			return fmt.Errorf("load installed manifest %s@%s: %w", id, ins.CurrentVersion, e)
		}
		finals[id] = v.Manifest
		versions[id] = ins.CurrentVersion
	}
	ids := make([]string, 0, len(finals))
	for id := range finals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i, a := range ids {
		for _, b := range ids[i+1:] {
			if conflictMatch(finals[a], b, versions[b]) || conflictMatch(finals[b], a, versions[a]) {
				return fmt.Errorf("extension conflict: %s@%s conflicts with %s@%s", a, versions[a], b, versions[b])
			}
		}
	}
	return nil
}
func topologicalOrder(selected map[string]selection) ([]string, error) {
	marks := map[string]int{}
	var out []string
	var stack []string
	var visit func(string) error
	visit = func(id string) error {
		if marks[id] == 2 {
			return nil
		}
		if marks[id] == 1 {
			return fmt.Errorf("dependency cycle detected: %s -> %s", strings.Join(stack, " -> "), id)
		}
		marks[id] = 1
		stack = append(stack, id)
		deps := append([]model.ExtensionDependency(nil), selected[id].item.Manifest.Dependencies...)
		sort.Slice(deps, func(i, j int) bool { return deps[i].ID < deps[j].ID })
		for _, d := range deps {
			if _, ok := selected[d.ID]; ok {
				if err := visit(d.ID); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		marks[id] = 2
		out = append(out, id)
		return nil
	}
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return out, nil
}
