package libxl

import (
	"fmt"
)

// Context represents a libxl context.
type Context struct {
	*Ctx
}

// NewContext returns a new libxl context.
func NewContext() (*Context, error) {
	c := Context{
		Ctx: NewCtx(),
	}

	if ret := ctxAlloc(&c.Ctx, version, 0, nil); ret != 0 {
		return nil, fmt.Errorf("unable to alloc new context: %v", ret)
	}

	return &c, nil
}

// Close closes and frees the libxl context.
func (c *Context) Close() error {
	if ret := ctxFree(c.Ctx); ret != 0 {
		return fmt.Errorf("unable to free context: %v", ret)
	}

	return nil
}

// DomainInfo returns the domain info for a given domain, identified
// by its domid.
func (c *Context) DomainInfo(domid DomID) (*DomInfo, error) {
	di := DomInfo{}

	if ret := domainInfo(c.Ctx, &di, uint32(domid)); ret != 0 {
		return nil, fmt.Errorf("unable to retrieve domain info: %v", ret)
	}
	di.Deref()

	return &di, nil
}

// DomainExists returns a bool indicating if the domain exists.
func (c *Context) DomainExists(domid DomID) bool {
	return domainInfo(c.Ctx, nil, uint32(domid)) != int32(errorDomainNotfound)
}

// CreateDomain creates a new domain with a given DomainConfig.
func (c *Context) CreateDomain(config *DomainConfig) (DomID, error) {
	// Call libxl_domain_create_now synchronously. An asynchronous API
	// may be added separately.

	// Begin with invalid domid
	domid := ^uint32(0)

	if ret := domainCreateNew(c.Ctx, config, &domid, nil, nil); ret != 0 {
		return DomID(domid), fmt.Errorf("unable to create domain: %v", ret)
	}

	return DomID(domid), nil
}

// ShutdownDomain shuts down a domain, specified by its domid.
func (c *Context) ShutdownDomain(domid DomID) error {
	if ret := domainShutdown(c.Ctx, uint32(domid)); ret != 0 {
		return fmt.Errorf("unable to shutdown domain: %v", ret)
	}

	return nil
}

// RebootDomain reboots a domain, specified by its domid.
func (c *Context) RebootDomain(domid DomID) error {
	if ret := domainReboot(c.Ctx, uint32(domid)); ret != 0 {
		return fmt.Errorf("unable to reboot domain: %v", ret)
	}

	return nil
}

// DestroyDomain destroys a domain, specified by its domid.
func (c *Context) DestroyDomain(domid DomID) error {
	if ret := domainDestroy(c.Ctx, uint32(domid), nil); ret != 0 {
		return fmt.Errorf("unable to destroy domain: %v", ret)
	}

	return nil
}
