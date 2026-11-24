package aigateway

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Monetary amounts are integer USD micro-units. Rates are micro-USD per million
// tokens, configured as conservative ceilings by the operator, not client input.
type Config struct {
	Key, Model                                       string
	Roles                                            map[string]bool
	InputCeiling, OutputLimit, InputRate, OutputRate int64
	GlobalBudget, UserBudget, UserRPM                int64
	MaxConcurrent                                    int
	Timeout                                          time.Duration
}

func FromEnv(get func(string) string) (Config, bool, error) {
	var c Config
	enabled := strings.TrimSpace(get("LAUNCHER_AI_ENABLED"))
	if enabled == "" || enabled == "false" {
		return c, false, nil
	}
	if enabled != "true" {
		return c, false, errors.New("LAUNCHER_AI_ENABLED must be true or false")
	}
	c.Key = strings.TrimSpace(get("LAUNCHER_AI_OPENAI_API_KEY"))
	c.Model = strings.TrimSpace(get("LAUNCHER_AI_MODEL"))
	if c.Key == "" || strings.ContainsAny(c.Key, "\r\n") || len(c.Key) > 4096 || c.Model == "" || len(c.Model) > 128 || strings.ContainsAny(c.Model, " \r\n\t") {
		return c, false, errors.New("AI key and model must be configured")
	}
	c.Roles = map[string]bool{}
	for _, role := range strings.Split(get("LAUNCHER_AI_ALLOWED_ROLES"), ",") {
		if role = strings.TrimSpace(role); role != "" && role != "*" {
			c.Roles[role] = true
		}
	}
	if len(c.Roles) == 0 {
		return c, false, errors.New("AI role allowlist required")
	}
	number := func(name string, min, max int64, fallback string) (int64, error) {
		v := strings.TrimSpace(get("LAUNCHER_AI_" + name))
		if v == "" {
			v = fallback
		}
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil || n < min || n > max {
			return 0, fmt.Errorf("invalid LAUNCHER_AI_%s", name)
		}
		return n, nil
	}
	fields := []struct {
		p        *int64
		name     string
		min, max int64
		fallback string
	}{
		{&c.InputCeiling, "INPUT_TOKEN_CEILING", 1024, 10_000_000, ""}, {&c.OutputLimit, "MAX_OUTPUT_TOKENS", 16, 32768, "1024"},
		{&c.InputRate, "INPUT_RATE_MICROUSD_PER_MILLION", 1, 1_000_000_000, ""}, {&c.OutputRate, "OUTPUT_RATE_MICROUSD_PER_MILLION", 1, 1_000_000_000, ""},
		{&c.GlobalBudget, "MONTHLY_BUDGET_MICROUSD", 1, 1_000_000_000_000, ""}, {&c.UserBudget, "USER_MONTHLY_BUDGET_MICROUSD", 1, 1_000_000_000_000, ""}, {&c.UserRPM, "USER_RPM", 1, 120, "6"},
	}
	for _, f := range fields {
		n, e := number(f.name, f.min, f.max, f.fallback)
		if e != nil {
			return c, false, e
		}
		*f.p = n
	}
	n, e := number("MAX_CONCURRENT", 1, 64, "4")
	if e != nil {
		return c, false, e
	}
	c.MaxConcurrent = int(n)
	c.Timeout = 90 * time.Second
	if c.UserBudget > c.GlobalBudget || c.ReserveCost() > c.UserBudget {
		return c, false, errors.New("AI budget smaller than maximum reservation or user budget exceeds global budget")
	}
	return c, true, nil
}

func cost(tokens, rate int64) int64 { return (tokens*rate + 999999) / 1000000 }
func (c Config) ReserveCost() int64 {
	return cost(c.InputCeiling, c.InputRate) + cost(c.OutputLimit, c.OutputRate)
}
func (c Config) Cost(input, output int64) int64 {
	return cost(input, c.InputRate) + cost(output, c.OutputRate)
}
