/*
 * Copyright (C) 2019 Nick Rosbrook, Assured Information Security, Inc.
 * Copyright (C) 2016 George W. Dunlap, Citrix Systems UK Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

// Package xenlight provides bindings to libxenlight (libxl).
package xenlight

/*
#cgo LDFLAGS: -lxenlight -lyajl -lxentoollog
#include <stdlib.h>
#include <libxl.h>
*/
import "C"

/*
 * Other flags that may be needed at some point:
 *  -lnl-route-3 -lnl-3
 *
 * To get back to static linking:
 * #cgo LDFLAGS: -lxenlight -lyajl_s -lxengnttab -lxenstore -lxenguest -lxentoollog -lxenevtchn -lxenctrl -lxenforeignmemory -lxencall -lz -luuid -lutil
 */

import (
	"fmt"
	"unsafe"
)

var libxlErrors = [...]string{
	-ErrorNonspecific:                  "Non-specific error",
	-ErrorVersion:                      "Wrong version",
	-ErrorFail:                         "Failed",
	-ErrorNi:                           "Not Implemented",
	-ErrorNomem:                        "No memory",
	-ErrorInval:                        "Invalid argument",
	-ErrorBadfail:                      "Bad Fail",
	-ErrorGuestTimedout:                "Guest timed out",
	-ErrorTimedout:                     "Timed out",
	-ErrorNoparavirt:                   "No Paravirtualization",
	-ErrorNotReady:                     "Not ready",
	-ErrorOseventRegFail:               "OS event registration failed",
	-ErrorBufferfull:                   "Buffer full",
	-ErrorUnknownChild:                 "Unknown child",
	-ErrorLockFail:                     "Lock failed",
	-ErrorJsonConfigEmpty:              "JSON config empty",
	-ErrorDeviceExists:                 "Device exists",
	-ErrorCheckpointDevopsDoesNotMatch: "Checkpoint devops does not match",
	-ErrorCheckpointDeviceNotSupported: "Checkpoint device not supported",
	-ErrorVnumaConfigInvalid:           "VNUMA config invalid",
	-ErrorDomainNotfound:               "Domain not found",
	-ErrorAborted:                      "Aborted",
	-ErrorNotfound:                     "Not found",
	-ErrorDomainDestroyed:              "Domain destroyed",
	-ErrorFeatureRemoved:               "Feature removed",
}

func (e Error) Error() string {
	if 0 < int(e) && int(e) < len(libxlErrors) {
		s := libxlErrors[e]
		if s != "" {
			return s
		}
	}
	return fmt.Sprintf("libxl error: %d", -e)
}

/*
 * Types: Builtins
 */

// Domid is a domain ID.
type Domid uint32

// Devid is a device ID.
type Devid int

// Uuid is a domain UUID.
type Uuid [16]byte

// String formats a Uuid in the form "xxxx-xx-xx-xx-xxxxxx".
func (u Uuid) String() string {
	s := "%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x"
	opts := make([]interface{}, 16)

	for i, v := range u {
		opts[i] = v
	}

	return fmt.Sprintf(s, opts...)
}

func (u *Uuid) fromC(c *C.libxl_uuid) error {
	b := (*[16]C.uint8_t)(unsafe.Pointer(&c.uuid[0]))

	for i, v := range b {
		u[i] = byte(v)
	}

	return nil
}

func (u *Uuid) toC() (C.libxl_uuid, error) {
	var c C.libxl_uuid

	for i, v := range u {
		c.uuid[i] = C.uint8_t(v)
	}

	return c, nil
}

// Hwcap represents a libxl_hwcap.
type Hwcap [8]uint32

func (hwcap *Hwcap) fromC(chwcap *C.libxl_hwcap) error {
	// Make a slice pointing to the C array
	mapslice := (*[8]C.uint32_t)(unsafe.Pointer(chwcap))

	// And copy the C array into the Go array
	for i, v := range mapslice {
		hwcap[i] = uint32(v)
	}

	return nil
}

func (hwcap *Hwcap) toC() (C.libxl_hwcap, error) {
	var chwcap C.libxl_hwcap

	for i, v := range hwcap {
		chwcap[i] = C.uint32_t(v)
	}

	return chwcap, nil
}

// Defbool represents a libxl_defbool.
type Defbool struct {
	val int
}

func (d *Defbool) fromC(c *C.libxl_defbool) error {
	d.val = int(c.val)
	return nil
}

func (d *Defbool) toC() (C.libxl_defbool, error) {
	c := C.libxl_defbool{val: C.int(d.val)}
	return c, nil
}

// KeyValueList represents a libxl_key_value_list.
type KeyValueList map[string]string

func (kvl KeyValueList) fromC(ckvl *C.libxl_key_value_list) error {
	size := int(C.libxl_key_value_list_length(ckvl))
	list := (*[1 << 30]*C.char)(unsafe.Pointer(ckvl))[:size:size]

	for i := 0; i < size*2; i += 2 {
		kvl[C.GoString(list[i])] = C.GoString(list[i+1])
	}

	return nil
}

func (kvl KeyValueList) toC() (C.libxl_key_value_list, error) {
	// Add extra slot for sentinel
	var char *C.char
	csize := 2*len(kvl) + 1
	ckvl := (C.libxl_key_value_list)(C.malloc(C.ulong(csize) * C.ulong(unsafe.Sizeof(char))))
	clist := (*[1 << 31]*C.char)(unsafe.Pointer(ckvl))[:csize:csize]

	i := 0
	for k, v := range kvl {
		clist[i] = C.CString(k)
		clist[i+1] = C.CString(v)
		i += 2
	}
	clist[len(clist)-1] = nil

	return ckvl, nil
}

// StringList represents a libxl_string_list.
type StringList []string

func (sl StringList) fromC(csl *C.libxl_string_list) error {
	size := int(C.libxl_string_list_length(csl))
	list := (*[1 << 30]*C.char)(unsafe.Pointer(csl))[:size:size]

	sl = make([]string, size)

	for i, v := range list {
		sl[i] = C.GoString(v)
	}

	return nil
}

func (sl StringList) toC() (C.libxl_string_list, error) {
	var char *C.char
	size := len(sl)
	csl := (C.libxl_string_list)(C.malloc(C.ulong(size) * C.ulong(unsafe.Sizeof(char))))
	clist := (*[1 << 30]*C.char)(unsafe.Pointer(csl))[:size:size]

	for i, v := range sl {
		clist[i] = C.CString(v)
	}

	return csl, nil
}

// CpuidPolicyList represents a libxl_cpuid_policy_list.
type CpuidPolicyList struct {
	val *C.libxl_cpuid_policy_list
}

func (cpl *CpuidPolicyList) fromC(ccpl *C.libxl_cpuid_policy_list) error {
	cpl.val = ccpl
	return nil
}

func (cpl *CpuidPolicyList) toC() (C.libxl_cpuid_policy_list, error) {
	if cpl.val == nil {
		var c C.libxl_cpuid_policy_list
		return c, nil
	}

	ccpl := (*C.libxl_cpuid_policy_list)(unsafe.Pointer(cpl.val))
	return *ccpl, nil
}

// MsVmGenid represents a libxl_ms_vm_genid.
type MsVmGenid [int(C.LIBXL_MS_VM_GENID_LEN)]byte

func (mvg *MsVmGenid) fromC(cmvg *C.libxl_ms_vm_genid) error {
	b := (*[int(C.LIBXL_MS_VM_GENID_LEN)]C.uint8_t)(unsafe.Pointer(&cmvg.bytes[0]))

	for i, v := range b {
		mvg[i] = byte(v)
	}

	return nil
}

func (mvg *MsVmGenid) toC() (C.libxl_ms_vm_genid, error) {
	var cmvg C.libxl_ms_vm_genid

	for i, v := range mvg {
		cmvg.bytes[i] = C.uint8_t(v)
	}

	return cmvg, nil
}

// Mac represents a libxl_mac, or simply a MAC address.
type Mac [6]byte

// String formats a Mac address to string representation.
func (mac Mac) String() string {
	s := "%x:%x:%x:%x:%x:%x"
	opts := make([]interface{}, 6)

	for i, v := range mac {
		opts[i] = v
	}

	return fmt.Sprintf(s, opts...)
}

func (mac *Mac) fromC(cmac *C.libxl_mac) error {
	b := (*[6]C.uint8_t)(unsafe.Pointer(cmac))

	for i, v := range b {
		mac[i] = byte(v)
	}

	return nil
}

func (mac *Mac) toC() (C.libxl_mac, error) {
	var cmac C.libxl_mac

	for i, v := range mac {
		cmac[i] = C.uint8_t(v)
	}

	return cmac, nil
}

// EvLink represents a libxl_ev_link.
//
// Represented as an empty struct for now, as there is no
// apparent need for the internals of this type to be exposed
// through the Go package.
type EvLink struct{}

func (el *EvLink) fromC(cel *C.libxl_ev_link) error      { return nil }
func (el *EvLink) toC() (cel C.libxl_ev_link, err error) { return }

// Bitmap represents a libxl_bitmap.
//
// Implement the Go bitmap type such that the underlying data can
// easily be copied in and out.  NB that we still have to do copies
// both directions, because cgo runtime restrictions forbid passing to
// a C function a pointer to a Go-allocated structure which contains a
// pointer.
type Bitmap struct {
	// typedef struct {
	//     uint32_t size;          /* number of bytes in map */
	//     uint8_t *map;
	// } libxl_bitmap;
	bitmap []C.uint8_t
}

func (bm *Bitmap) fromC(cbm *C.libxl_bitmap) error {
	// Alloc a Go slice for the bytes
	size := int(cbm.size)
	bm.bitmap = make([]C.uint8_t, size)

	// Make a slice pointing to the C array
	mapslice := (*[1 << 30]C.uint8_t)(unsafe.Pointer(cbm._map))[:size:size]

	// And copy the C array into the Go array
	copy(bm.bitmap, mapslice)

	return nil
}

func (bm *Bitmap) toC() (C.libxl_bitmap, error) {
	var cbm C.libxl_bitmap

	size := len(bm.bitmap)
	cbm.size = C.uint32_t(size)
	cbm._map = (*C.uint8_t)(C.malloc(C.ulong(cbm.size) * C.sizeof_uint8_t))
	cslice := (*[1 << 31]C.uint8_t)(unsafe.Pointer(cbm._map))[:size:size]

	copy(cslice, bm.bitmap)

	return cbm, nil
}

// Context represents a libxl_ctx.
type Context struct {
	ctx    *C.libxl_ctx
	logger *C.xentoollog_logger_stdiostream
}

// NewContext returns a new Context.
func NewContext() (*Context, error) {
	var ctx Context

	ctx.logger = C.xtl_createlogger_stdiostream(C.stderr, C.XTL_ERROR, 0)

	ret := C.libxl_ctx_alloc(&ctx.ctx, C.LIBXL_VERSION, 0, (*C.xentoollog_logger)(unsafe.Pointer(ctx.logger)))
	if ret != 0 {
		return nil, Error(ret)
	}

	return &ctx, nil
}

// Close closes the Context.
func (ctx *Context) Close() error {
	ret := C.libxl_ctx_free(ctx.ctx)
	ctx.ctx = nil
	C.xtl_logger_destroy((*C.xentoollog_logger)(unsafe.Pointer(ctx.logger)))

	if ret != 0 {
		return Error(ret)
	}

	return nil
}

// DomainInfo returns the domain info for a domain, given its Domid.
func (ctx *Context) DomainInfo(domid Domid) (*Dominfo, error) {
	var (
		di  Dominfo
		cdi C.libxl_dominfo
	)
	C.libxl_dominfo_init(&cdi)
	defer C.libxl_dominfo_dispose(&cdi)

	ret := C.libxl_domain_info(ctx.ctx, &cdi, C.uint32_t(domid))
	if ret != 0 {
		return nil, Error(ret)
	}

	if err := di.fromC(&cdi); err != nil {
		return nil, err
	}

	return &di, nil
}

// CreateDomain creates a domain with the given DomainConfig. On success, the
// Domid of the new domain is returned.
func (ctx *Context) CreateDomain(cfg DomainConfig) (Domid, error) {
	domid := Domid(^uint32(0))

	cdc, err := cfg.toC()
	if err != nil {
		return domid, err
	}
	defer C.libxl_domain_config_dispose(&cdc)

	var cdomid C.uint32_t

	// Do the domain creation synchronously.
	ret := C.libxl_domain_create_new(ctx.ctx, &cdc, &cdomid, nil, nil)
	if ret != 0 {
		return domid, Error(-ret)
	}
	domid = Domid(cdomid)

	return domid, nil
}

// libxl_cpupoolinfo * libxl_list_cpupool(libxl_ctx*, int *nb_pool_out);
// void libxl_cpupoolinfo_list_free(libxl_cpupoolinfo *list, int nb_pool);
func (ctx *Context) ListCpupool() (list []Cpupoolinfo, err error) {
	var nbPool C.int

	c_cpupool_list := C.libxl_list_cpupool(ctx.ctx, &nbPool)

	defer C.libxl_cpupoolinfo_list_free(c_cpupool_list, nbPool)

	if int(nbPool) == 0 {
		return
	}

	// Magic
	cpupoolListSlice := (*[1 << 30]C.libxl_cpupoolinfo)(unsafe.Pointer(c_cpupool_list))[:nbPool:nbPool]
	for i := range cpupoolListSlice {
		var ci Cpupoolinfo
		err = ci.fromC(&cpupoolListSlice[i])
		if err != nil {
			return
		}
		list = append(list, ci)
	}

	return
}

// int libxl_cpupool_info(libxl_ctx *ctx, libxl_cpupoolinfo *info, uint32_t poolid);
func (ctx *Context) Cpupoolinfo(Poolid uint32) (pool Cpupoolinfo, err error) {
	var c_cpupool C.libxl_cpupoolinfo

	ret := C.libxl_cpupool_info(ctx.ctx, &c_cpupool, C.uint32_t(Poolid))
	if ret != 0 {
		err = Error(-ret)
		return
	}
	defer C.libxl_cpupoolinfo_dispose(&c_cpupool)

	err = pool.fromC(&c_cpupool)
	if err != nil {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_create(libxl_ctx *ctx, const char *name,
//                          libxl_scheduler sched,
//                          libxl_bitmap cpumap, libxl_uuid *uuid,
//                          uint32_t *poolid);
// FIXME: uuid
// FIXME: Setting poolid
func (ctx *Context) CpupoolCreate(Name string, Scheduler Scheduler, Cpumap Bitmap) (err error, Poolid uint32) {
	poolid := C.uint32_t(C.LIBXL_CPUPOOL_POOLID_ANY)
	name := C.CString(Name)
	defer C.free(unsafe.Pointer(name))

	// For now, just do what xl does, and make a new uuid every time we create the pool
	var uuid C.libxl_uuid
	C.libxl_uuid_generate(&uuid)

	cbm, err := Cpumap.toC()
	if err != nil {
		return
	}
	defer C.libxl_bitmap_dispose(&cbm)

	ret := C.libxl_cpupool_create(ctx.ctx, name, C.libxl_scheduler(Scheduler),
		cbm, &uuid, &poolid)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	Poolid = uint32(poolid)

	return
}

// int libxl_cpupool_destroy(libxl_ctx *ctx, uint32_t poolid);
func (ctx *Context) CpupoolDestroy(Poolid uint32) (err error) {
	ret := C.libxl_cpupool_destroy(ctx.ctx, C.uint32_t(Poolid))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuadd(libxl_ctx *ctx, uint32_t poolid, int cpu);
func (ctx *Context) CpupoolCpuadd(Poolid uint32, Cpu int) (err error) {
	ret := C.libxl_cpupool_cpuadd(ctx.ctx, C.uint32_t(Poolid), C.int(Cpu))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuadd_cpumap(libxl_ctx *ctx, uint32_t poolid,
//                                 const libxl_bitmap *cpumap);
func (ctx *Context) CpupoolCpuaddCpumap(Poolid uint32, Cpumap Bitmap) (err error) {
	cbm, err := Cpumap.toC()
	if err != nil {
		return
	}
	defer C.libxl_bitmap_dispose(&cbm)

	ret := C.libxl_cpupool_cpuadd_cpumap(ctx.ctx, C.uint32_t(Poolid), &cbm)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuremove(libxl_ctx *ctx, uint32_t poolid, int cpu);
func (ctx *Context) CpupoolCpuremove(Poolid uint32, Cpu int) (err error) {
	ret := C.libxl_cpupool_cpuremove(ctx.ctx, C.uint32_t(Poolid), C.int(Cpu))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuremove_cpumap(libxl_ctx *ctx, uint32_t poolid,
//                                    const libxl_bitmap *cpumap);
func (ctx *Context) CpupoolCpuremoveCpumap(Poolid uint32, Cpumap Bitmap) (err error) {
	cbm, err := Cpumap.toC()
	if err != nil {
		return
	}
	defer C.libxl_bitmap_dispose(&cbm)

	ret := C.libxl_cpupool_cpuremove_cpumap(ctx.ctx, C.uint32_t(Poolid), &cbm)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_rename(libxl_ctx *ctx, const char *name, uint32_t poolid);
func (ctx *Context) CpupoolRename(Name string, Poolid uint32) (err error) {
	name := C.CString(Name)
	defer C.free(unsafe.Pointer(name))

	ret := C.libxl_cpupool_rename(ctx.ctx, name, C.uint32_t(Poolid))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuadd_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus);
func (ctx *Context) CpupoolCpuaddNode(Poolid uint32, Node int) (Cpus int, err error) {
	ccpus := C.int(0)

	ret := C.libxl_cpupool_cpuadd_node(ctx.ctx, C.uint32_t(Poolid), C.int(Node), &ccpus)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	Cpus = int(ccpus)

	return
}

// int libxl_cpupool_cpuremove_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus);
func (ctx *Context) CpupoolCpuremoveNode(Poolid uint32, Node int) (Cpus int, err error) {
	ccpus := C.int(0)

	ret := C.libxl_cpupool_cpuremove_node(ctx.ctx, C.uint32_t(Poolid), C.int(Node), &ccpus)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	Cpus = int(ccpus)

	return
}

// int libxl_cpupool_movedomain(libxl_ctx *ctx, uint32_t poolid, uint32_t domid);
func (ctx *Context) CpupoolMovedomain(Poolid uint32, Id Domid) (err error) {
	ret := C.libxl_cpupool_movedomain(ctx.ctx, C.uint32_t(Poolid), C.uint32_t(Id))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

//
// Utility functions
//
func (ctx *Context) CpupoolFindByName(name string) (info Cpupoolinfo, found bool) {
	plist, err := ctx.ListCpupool()
	if err != nil {
		return
	}

	for i := range plist {
		if plist[i].PoolName == name {
			found = true
			info = plist[i]
			return
		}
	}
	return
}

func (ctx *Context) CpupoolMakeFree(Cpumap Bitmap) (err error) {
	plist, err := ctx.ListCpupool()
	if err != nil {
		return
	}

	for i := range plist {
		var Intersection Bitmap
		Intersection = Cpumap.And(plist[i].Cpumap)
		if !Intersection.IsEmpty() {
			err = ctx.CpupoolCpuremoveCpumap(plist[i].Poolid, Intersection)
			if err != nil {
				return
			}
		}
	}
	return
}

/*
 * Bitmap operations
 */
func (bm *Bitmap) Test(bit int) bool {
	ubit := uint(bit)
	if bit > bm.Max() || bm.bitmap == nil {
		return false
	}

	return (bm.bitmap[bit/8] & (1 << (ubit & 7))) != 0
}

func (bm *Bitmap) Set(bit int) {
	ibit := bit / 8
	if ibit+1 > len(bm.bitmap) {
		bm.bitmap = append(bm.bitmap, make([]C.uint8_t, ibit+1-len(bm.bitmap))...)
	}

	bm.bitmap[ibit] |= 1 << (uint(bit) & 7)
}

func (bm *Bitmap) SetRange(start int, end int) {
	for i := start; i <= end; i++ {
		bm.Set(i)
	}
}

func (bm *Bitmap) Clear(bit int) {
	ubit := uint(bit)
	if bit > bm.Max() || bm.bitmap == nil {
		return
	}

	bm.bitmap[bit/8] &= ^(1 << (ubit & 7))
}

func (bm *Bitmap) ClearRange(start int, end int) {
	for i := start; i <= end; i++ {
		bm.Clear(i)
	}
}

func (bm *Bitmap) Max() int {
	return len(bm.bitmap)*8 - 1
}

func (bm *Bitmap) IsEmpty() bool {
	for i := 0; i < len(bm.bitmap); i++ {
		if bm.bitmap[i] != 0 {
			return false
		}
	}
	return true
}

func (a Bitmap) And(b Bitmap) (c Bitmap) {
	var max, min int
	if len(a.bitmap) > len(b.bitmap) {
		max = len(a.bitmap)
		min = len(b.bitmap)
	} else {
		max = len(b.bitmap)
		min = len(a.bitmap)
	}
	c.bitmap = make([]C.uint8_t, max)

	for i := 0; i < min; i++ {
		c.bitmap[i] = a.bitmap[i] & b.bitmap[i]
	}
	return
}

func (bm Bitmap) String() (s string) {
	lastOnline := false
	crange := false
	printed := false
	var i int
	/// --x-xxxxx-x -> 2,4-8,10
	/// --x-xxxxxxx -> 2,4-10
	for i = 0; i <= bm.Max(); i++ {
		if bm.Test(i) {
			if !lastOnline {
				// Switching offline -> online, print this cpu
				if printed {
					s += ","
				}
				s += fmt.Sprintf("%d", i)
				printed = true
			} else if !crange {
				// last was online, but we're not in a range; print -
				crange = true
				s += "-"
			} else {
				// last was online, we're in a range,  nothing else to do
			}
			lastOnline = true
		} else {
			if lastOnline {
				// Switching online->offline; do we need to end a range?
				if crange {
					s += fmt.Sprintf("%d", i-1)
				}
			}
			lastOnline = false
			crange = false
		}
	}
	if lastOnline {
		// Switching online->offline; do we need to end a range?
		if crange {
			s += fmt.Sprintf("%d", i-1)
		}
	}

	return
}

//int libxl_get_max_cpus(libxl_ctx *ctx);
func (ctx *Context) GetMaxCpus() (maxCpus int, err error) {
	ret := C.libxl_get_max_cpus(ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	maxCpus = int(ret)
	return
}

//int libxl_get_online_cpus(libxl_ctx *ctx);
func (ctx *Context) GetOnlineCpus() (onCpus int, err error) {
	ret := C.libxl_get_online_cpus(ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	onCpus = int(ret)
	return
}

//int libxl_get_max_nodes(libxl_ctx *ctx);
func (ctx *Context) GetMaxNodes() (maxNodes int, err error) {
	ret := C.libxl_get_max_nodes(ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	maxNodes = int(ret)
	return
}

//int libxl_get_free_memory(libxl_ctx *ctx, uint64_t *memkb);
func (ctx *Context) GetFreeMemory() (memkb uint64, err error) {
	var cmem C.uint64_t
	ret := C.libxl_get_free_memory(ctx.ctx, &cmem)

	if ret < 0 {
		err = Error(-ret)
		return
	}

	memkb = uint64(cmem)
	return

}

//int libxl_get_physinfo(libxl_ctx *ctx, libxl_physinfo *physinfo)
func (ctx *Context) GetPhysinfo() (physinfo *Physinfo, err error) {
	var cphys C.libxl_physinfo
	C.libxl_physinfo_init(&cphys)
	defer C.libxl_physinfo_dispose(&cphys)

	ret := C.libxl_get_physinfo(ctx.ctx, &cphys)

	if ret < 0 {
		err = Error(ret)
		return
	}
	err = physinfo.fromC(&cphys)

	return
}

//const libxl_version_info* libxl_get_version_info(libxl_ctx *ctx);
func (ctx *Context) GetVersionInfo() (info *VersionInfo, err error) {
	var cinfo *C.libxl_version_info

	cinfo = C.libxl_get_version_info(ctx.ctx)

	err = info.fromC(cinfo)

	return
}

func (ctx *Context) DomainUnpause(Id Domid) (err error) {
	ret := C.libxl_domain_unpause(ctx.ctx, C.uint32_t(Id))

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

//int libxl_domain_pause(libxl_ctx *ctx, uint32_t domain);
func (ctx *Context) DomainPause(id Domid) (err error) {
	ret := C.libxl_domain_pause(ctx.ctx, C.uint32_t(id))

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

//int libxl_domain_shutdown(libxl_ctx *ctx, uint32_t domid);
func (ctx *Context) DomainShutdown(id Domid) (err error) {
	ret := C.libxl_domain_shutdown(ctx.ctx, C.uint32_t(id))

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

//int libxl_domain_reboot(libxl_ctx *ctx, uint32_t domid);
func (ctx *Context) DomainReboot(id Domid) (err error) {
	ret := C.libxl_domain_reboot(ctx.ctx, C.uint32_t(id))

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

//libxl_dominfo * libxl_list_domain(libxl_ctx*, int *nb_domain_out);
//void libxl_dominfo_list_free(libxl_dominfo *list, int nb_domain);
func (ctx *Context) ListDomain() (glist []Dominfo, err error) {
	var nbDomain C.int
	clist := C.libxl_list_domain(ctx.ctx, &nbDomain)
	defer C.libxl_dominfo_list_free(clist, nbDomain)

	if int(nbDomain) == 0 {
		return
	}

	gslice := (*[1 << 30]C.libxl_dominfo)(unsafe.Pointer(clist))[:nbDomain:nbDomain]
	for i := range gslice {
		var di Dominfo
		err = di.fromC(&gslice[i])
		if err != nil {
			return
		}
		glist = append(glist, di)
	}

	return
}

//libxl_vcpuinfo *libxl_list_vcpu(libxl_ctx *ctx, uint32_t domid,
//				int *nb_vcpu, int *nr_cpus_out);
//void libxl_vcpuinfo_list_free(libxl_vcpuinfo *, int nr_vcpus);
func (ctx *Context) ListVcpu(id Domid) (glist []Vcpuinfo, err error) {
	var nbVcpu C.int
	var nrCpu C.int

	clist := C.libxl_list_vcpu(ctx.ctx, C.uint32_t(id), &nbVcpu, &nrCpu)
	defer C.libxl_vcpuinfo_list_free(clist, nbVcpu)

	if int(nbVcpu) == 0 {
		return
	}

	gslice := (*[1 << 30]C.libxl_vcpuinfo)(unsafe.Pointer(clist))[:nbVcpu:nbVcpu]
	for i := range gslice {
		var vi Vcpuinfo
		err = vi.fromC(&gslice[i])
		if err != nil {
			return
		}
		glist = append(glist, vi)
	}

	return
}

//int libxl_console_get_tty(libxl_ctx *ctx, uint32_t domid, int cons_num,
//libxl_console_type type, char **path);
func (ctx *Context) ConsoleGetTty(id Domid, consNum int, conType ConsoleType) (path string, err error) {
	var cpath *C.char
	ret := C.libxl_console_get_tty(ctx.ctx, C.uint32_t(id), C.int(consNum), C.libxl_console_type(conType), &cpath)
	if ret != 0 {
		err = Error(-ret)
		return
	}
	defer C.free(unsafe.Pointer(cpath))

	path = C.GoString(cpath)
	return
}

//int libxl_primary_console_get_tty(libxl_ctx *ctx, uint32_t domid_vm,
//					char **path);
func (ctx *Context) PrimaryConsoleGetTty(domid uint32) (path string, err error) {
	var cpath *C.char
	ret := C.libxl_primary_console_get_tty(ctx.ctx, C.uint32_t(domid), &cpath)
	if ret != 0 {
		err = Error(-ret)
		return
	}
	defer C.free(unsafe.Pointer(cpath))

	path = C.GoString(cpath)
	return
}
