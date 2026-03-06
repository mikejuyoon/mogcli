package auth

import (
	"fmt"
	"sort"
	"strings"
)

func DelegatedScopeWorkloadNames() []string {
	out := make([]string, len(delegatedScopeWorkloadOrder))
	copy(out, delegatedScopeWorkloadOrder)
	return out
}

func DelegatedScopeWorkloadsHelp() string {
	return strings.Join(delegatedScopeWorkloadOrder, ",")
}

func ParseScopeWorkloadsCSV(value string) ([]string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("missing delegated scope workloads (valid: %s)", DelegatedScopeWorkloadsHelp())
	}

	parts := strings.Split(trimmed, ",")
	return NormalizeScopeWorkloads(parts)
}

func NormalizeScopeWorkloads(workloads []string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, workload := range workloads {
		name := strings.ToLower(strings.TrimSpace(workload))
		if name == "" {
			continue
		}
		if _, ok := delegatedScopeWorkloadMap[name]; !ok {
			return nil, fmt.Errorf("invalid delegated scope workload %q (valid: %s)", name, DelegatedScopeWorkloadsHelp())
		}
		seen[name] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for _, workload := range delegatedScopeWorkloadOrder {
		if _, ok := seen[workload]; ok {
			out = append(out, workload)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("at least one delegated scope workload is required (valid: %s)", DelegatedScopeWorkloadsHelp())
	}

	return out, nil
}

func DelegatedScopesForWorkloads(workloads []string) ([]string, error) {
	normalized, err := NormalizeScopeWorkloads(workloads)
	if err != nil {
		return nil, err
	}

	scopes := make([]string, 0, len(BaseDelegatedScopes)+len(AllDelegatedWorkloadScopes))
	scopes = append(scopes, BaseDelegatedScopes...)
	for _, workload := range normalized {
		scopes = append(scopes, delegatedScopeWorkloadMap[workload]...)
	}

	return normalizeScopes(scopes), nil
}

func normalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}

	seen := map[string]string{}
	for _, scope := range scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; !ok {
			seen[key] = trimmed
		}
	}

	out := make([]string, 0, len(seen))
	for _, scope := range BaseDelegatedScopes {
		key := strings.ToLower(scope)
		if value, ok := seen[key]; ok {
			out = append(out, value)
			delete(seen, key)
		}
	}

	for _, scope := range AllDelegatedWorkloadScopes {
		key := strings.ToLower(scope)
		if value, ok := seen[key]; ok {
			out = append(out, value)
			delete(seen, key)
		}
	}

	extra := make([]string, 0, len(seen))
	for _, value := range seen {
		extra = append(extra, value)
	}
	sort.Strings(extra)
	out = append(out, extra...)

	return out
}

func scopeStringCoversRequiredScopes(grantedScopeString string, requiredScopes []string) bool {
	granted := normalizeScopes(strings.Fields(strings.TrimSpace(grantedScopeString)))
	required := normalizeScopes(requiredScopes)
	return scopeSetContainsAll(granted, required)
}

func scopeSetContainsAll(granted []string, required []string) bool {
	if len(required) == 0 {
		return true
	}

	grantedSet := map[string]struct{}{}
	for _, scope := range granted {
		key := strings.ToLower(strings.TrimSpace(scope))
		grantedSet[key] = struct{}{}
		// Azure AD returns scopes as full URLs (e.g.
		// "https://graph.microsoft.com/Mail.Read"). Also index by the
		// short form so callers using "Mail.Read" match correctly.
		if short := stripGraphPrefix(key); short != key {
			grantedSet[short] = struct{}{}
		}
	}

	// If the granted set contains .default, all Graph scopes are covered.
	if _, ok := grantedSet["https://graph.microsoft.com/.default"]; ok {
		return true
	}

	for _, scope := range required {
		if _, ok := grantedSet[strings.ToLower(strings.TrimSpace(scope))]; !ok {
			return false
		}
	}

	return true
}

const graphScopePrefix = "https://graph.microsoft.com/"

func stripGraphPrefix(scope string) string {
	if strings.HasPrefix(scope, graphScopePrefix) {
		return scope[len(graphScopePrefix):]
	}
	return scope
}
