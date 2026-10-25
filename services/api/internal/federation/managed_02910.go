package federation

import (
	"errors"
	"fmt"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

// SwapManaged replaces a live connector without closing one still in use by
// another request. Retired connections are closed during Core.Close.
func (c *Core) SwapManaged(connector authconnector.Connector, policy ProviderPolicy, revision int64) error {
	if err := authconnector.ValidateConnector(connector); err != nil {
		return err
	}
	id := authconnector.NormalizedMetadata(connector.Metadata()).ID
	// Policies are applied to real JIT users: do not accept unknown local
	// roles, including mappings which could otherwise elevate privileges.
	known := make(map[string]bool)
	for _, role := range c.repo.ListRoles() {
		known[role.ID] = true
	}
	if policy.AutoProvision && !known[policy.DefaultRole] {
		return fmt.Errorf("invalid default role %q", policy.DefaultRole)
	}
	for _, target := range policy.RoleMappings {
		if !known[target] {
			return fmt.Errorf("invalid mapped role %q", target)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == "local" {
		return errors.New("local provider cannot be replaced")
	}
	if _, exists := c.connectors[id]; exists {
		if _, owned := c.managedRevisions[id]; !owned {
			return fmt.Errorf("provider %q is controlled by bootstrap configuration", id)
		}
		c.retiredManaged = append(c.retiredManaged, c.connectors[id])
	}
	if c.managedRevisions == nil {
		c.managedRevisions = map[string]int64{}
	}
	c.connectors[id] = connector
	c.policies[id] = policy
	c.managedRevisions[id] = revision
	return nil
}
func (c *Core) ManagedRevision(id string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.managedRevisions[id]
}
func (c *Core) DisableManaged(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.connectors[id]; exists {
		if _, managed := c.managedRevisions[id]; !managed {
			return fmt.Errorf("provider %q is controlled by bootstrap configuration", id)
		}
		c.retiredManaged = append(c.retiredManaged, c.connectors[id])
		delete(c.connectors, id)
		delete(c.policies, id)
	}
	delete(c.managedRevisions, id)
	return nil
}
func (c *Core) WithManagedSync(fn func() error) error {
	c.managedSync.Lock()
	defer c.managedSync.Unlock()
	return fn()
}

func (c *Core) ManagedIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ids := make([]string, 0, len(c.managedRevisions))
	for id := range c.managedRevisions {
		ids = append(ids, id)
	}
	return ids
}
