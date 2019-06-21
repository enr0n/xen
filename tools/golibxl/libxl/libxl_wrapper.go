package libxl

import (
	"fmt"
)

// Context represents a libxl context.
type Context struct {
	x *Ctx
}

// NewContext returns a new libxl context.
func NewContext() (*Context, error) {
	c := Context{
		x: NewCtx(),
	}

	if ret := ctxAlloc(&c.x, Version, 0, nil); ret != 0 {
		return nil, fmt.Errorf("unable to alloc new context: %v", ret)
	}

	return &c, nil
}

func (c *Context) Close() error {
	if ret := ctxFree(c.x); ret != 0 {
		return fmt.Errorf("unable to free context: %v", ret)
	}

	return nil
}

// DomainInfo returns the domain info for a given domain, identified
// by its domid.
func (c *Context) DomainInfo(domid DomID) (*DomInfo, error) {
	di := DomInfo{}

	if ret := domainInfo(c.x, &di, uint32(domid)); ret != 0 {
		return nil, fmt.Errorf("unable to retrieve domain info: %v", ret)
	}

	return &di, nil
}
