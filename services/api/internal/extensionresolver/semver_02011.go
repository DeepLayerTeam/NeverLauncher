package extensionresolver

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Version struct {
	Major, Minor, Patch int
	Pre                 []string
	Raw                 string
}

func ParseVersion(raw string) (Version, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if raw == "" {
		return Version{}, errors.New("пустой SemVer")
	}
	corePre := strings.SplitN(strings.SplitN(raw, "+", 2)[0], "-", 2)
	core := strings.Split(corePre[0], ".")
	if len(core) < 2 || len(core) > 3 {
		return Version{}, fmt.Errorf("недопустимый SemVer %q", raw)
	}
	vals := []int{0, 0, 0}
	for i, p := range core {
		if p == "" {
			return Version{}, fmt.Errorf("недопустимый SemVer %q", raw)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("недопустимый SemVer %q", raw)
		}
		vals[i] = n
	}
	v := Version{Major: vals[0], Minor: vals[1], Patch: vals[2], Raw: raw}
	if len(corePre) == 2 {
		if corePre[1] == "" {
			return Version{}, fmt.Errorf("недопустимый SemVer предварительный релиз %q", raw)
		}
		v.Pre = strings.Split(corePre[1], ".")
	}
	return v, nil
}

func Compare(a, b Version) int {
	ints := [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}}
	for _, p := range ints {
		if p[0] < p[1] {
			return -1
		}
		if p[0] > p[1] {
			return 1
		}
	}
	if len(a.Pre) == 0 && len(b.Pre) == 0 {
		return 0
	}
	if len(a.Pre) == 0 {
		return 1
	}
	if len(b.Pre) == 0 {
		return -1
	}
	n := len(a.Pre)
	if len(b.Pre) > n {
		n = len(b.Pre)
	}
	for i := 0; i < n; i++ {
		if i >= len(a.Pre) {
			return -1
		}
		if i >= len(b.Pre) {
			return 1
		}
		ai, ae := strconv.Atoi(a.Pre[i])
		bi, be := strconv.Atoi(b.Pre[i])
		if ae == nil && be == nil {
			if ai < bi {
				return -1
			}
			if ai > bi {
				return 1
			}
			continue
		}
		if ae == nil && be != nil {
			return -1
		}
		if ae != nil && be == nil {
			return 1
		}
		if a.Pre[i] < b.Pre[i] {
			return -1
		}
		if a.Pre[i] > b.Pre[i] {
			return 1
		}
	}
	return 0
}

func normalizeConstraintVersion(s string) (Version, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "v"))
	parts := strings.SplitN(strings.SplitN(s, "+", 2)[0], "-", 2)
	core := strings.Split(parts[0], ".")
	if len(core) == 1 {
		s += ".0.0"
	} else if len(core) == 2 {
		s += ".0"
	}
	return ParseVersion(s)
}

type predicate func(Version) bool

type Constraint struct {
	Raw          string
	alternatives [][]predicate
}

func ParseConstraint(raw string) (Constraint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Constraint{}, errors.New("пустой SemVer ограничение")
	}
	if raw == "*" || strings.EqualFold(raw, "x") {
		return Constraint{Raw: raw, alternatives: [][]predicate{{func(Version) bool { return true }}}}, nil
	}
	ors := strings.Split(raw, "||")
	c := Constraint{Raw: raw}
	for _, altRaw := range ors {
		altRaw = strings.TrimSpace(strings.ReplaceAll(altRaw, ",", " "))
		if altRaw == "" {
			return Constraint{}, fmt.Errorf("недопустимый ограничение %q", raw)
		}
		toks := strings.Fields(altRaw)
		var preds []predicate
		for _, tok := range toks {
			ps, err := parseConstraintToken(tok)
			if err != nil {
				return Constraint{}, err
			}
			preds = append(preds, ps...)
		}
		c.alternatives = append(c.alternatives, preds)
	}
	return c, nil
}

func parseConstraintToken(tok string) ([]predicate, error) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return nil, nil
	}
	if tok == "*" || strings.EqualFold(tok, "x") {
		return []predicate{func(Version) bool { return true }}, nil
	}
	if strings.ContainsAny(tok, "xX*") {
		clean := strings.TrimPrefix(tok, "=")
		parts := strings.Split(clean, ".")
		nums := []int{}
		for _, p := range parts {
			if p == "x" || p == "X" || p == "*" {
				break
			}
			n, e := strconv.Atoi(p)
			if e != nil {
				return nil, fmt.Errorf("недопустимый маска ограничение %q", tok)
			}
			nums = append(nums, n)
		}
		if len(nums) == 0 {
			return []predicate{func(Version) bool { return true }}, nil
		}
		return []predicate{func(v Version) bool {
			if v.Major != nums[0] {
				return false
			}
			if len(nums) > 1 && v.Minor != nums[1] {
				return false
			}
			if len(nums) > 2 && v.Patch != nums[2] {
				return false
			}
			return true
		}}, nil
	}
	op := "="
	val := tok
	for _, candidate := range []string{">=", "<=", ">", "<", "^", "~", "="} {
		if strings.HasPrefix(tok, candidate) {
			op = candidate
			val = strings.TrimSpace(strings.TrimPrefix(tok, candidate))
			break
		}
	}
	v, err := normalizeConstraintVersion(val)
	if err != nil {
		return nil, fmt.Errorf("недопустимый ограничение %q: %w", tok, err)
	}
	switch op {
	case "=":
		return []predicate{func(x Version) bool { return Compare(x, v) == 0 }}, nil
	case ">=":
		return []predicate{func(x Version) bool { return Compare(x, v) >= 0 }}, nil
	case "<=":
		return []predicate{func(x Version) bool { return Compare(x, v) <= 0 }}, nil
	case ">":
		return []predicate{func(x Version) bool { return Compare(x, v) > 0 }}, nil
	case "<":
		return []predicate{func(x Version) bool { return Compare(x, v) < 0 }}, nil
	case "^":
		upper := v
		if v.Major > 0 {
			upper = Version{Major: v.Major + 1}
		} else if v.Minor > 0 {
			upper = Version{Minor: v.Minor + 1}
		} else {
			upper = Version{Patch: v.Patch + 1}
		}
		return []predicate{func(x Version) bool { return Compare(x, v) >= 0 }, func(x Version) bool { return Compare(x, upper) < 0 }}, nil
	case "~":
		upper := Version{Major: v.Major, Minor: v.Minor + 1}
		return []predicate{func(x Version) bool { return Compare(x, v) >= 0 }, func(x Version) bool { return Compare(x, upper) < 0 }}, nil
	default:
		return nil, fmt.Errorf("неподдерживаемый ограничение оператор %q", op)
	}
}

func (c Constraint) Match(v Version) bool {
	for _, alt := range c.alternatives {
		ok := true
		for _, p := range alt {
			if !p(v) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func Matches(version, constraint string) bool {
	v, e := ParseVersion(version)
	if e != nil {
		return false
	}
	c, e := ParseConstraint(constraint)
	return e == nil && c.Match(v)
}
