/*
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
	"time"
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

type Domid uint32

// Devid is a device ID.
type Devid int

type MemKB uint64

type Uuid C.libxl_uuid

// defboolVal represents a defbool value.
type defboolVal int

const (
	defboolDefault defboolVal = 0
	defboolFalse   defboolVal = -1
	defboolTrue    defboolVal = 1
)

// Defbool represents a libxl_defbool.
type Defbool struct {
	val defboolVal
}

func (d Defbool) String() string {
	switch d.val {
	case defboolDefault:
		return "<default>"
	case defboolFalse:
		return "False"
	case defboolTrue:
		return "True"
	}

	return ""
}

// Set sets the value of the Defbool.
func (d *Defbool) Set(b bool) {
	if b {
		d.val = defboolTrue
		return
	}
	d.val = defboolFalse
}

// Unset resets the Defbool to default value.
func (d *Defbool) Unset() {
	d.val = defboolDefault
}

// SetIfDefault sets the value of Defbool only if
// its current value is default.
func (d *Defbool) SetIfDefault(b bool) {
	if d.IsDefault() {
		d.Set(b)
	}
}

// IsDefault returns true if the value of Defbool
// is default, returns false otherwise.
func (d *Defbool) IsDefault() bool {
	return d.val == defboolDefault
}

// Val returns the boolean value associated with the
// Defbool value. An error is returned if the value
// is default.
func (d *Defbool) Val() (bool, error) {
	if d.IsDefault() {
		return false, fmt.Errorf("%v: cannot take value of default defbool", ErrorInval)
	}

	return (d.val > 0), nil
}

func (d *Defbool) fromC(c *C.libxl_defbool) error {
	if C.libxl_defbool_is_default(*c) {
		d.val = defboolDefault
		return nil
	}

	if C.libxl_defbool_val(*c) {
		d.val = defboolTrue
		return nil
	}

	d.val = defboolFalse

	return nil
}

func (d *Defbool) toC() (C.libxl_defbool, error) {
	var c C.libxl_defbool

	if !d.IsDefault() {
		val, _ := d.Val()
		C.libxl_defbool_set(&c, C.bool(val))
	}

	return c, nil
}

// Mac represents a libxl_mac, or simply a MAC address.
type Mac [6]byte

// String formats a Mac address to string representation.
func (mac Mac) String() string {
	s := "%02x:%02x:%02x:%02x:%02x:%02x"
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

func (mac Mac) toC() (C.libxl_mac, error) {
	var cmac C.libxl_mac

	for i, v := range mac {
		cmac[i] = C.uint8_t(v)
	}

	return cmac, nil
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

type Context struct {
	ctx    *C.libxl_ctx
	logger *C.xentoollog_logger_stdiostream
}

type Hwcap []C.uint32_t

func (chwcap C.libxl_hwcap) toGo() (ghwcap Hwcap) {
	// Alloc a Go slice for the bytes
	size := 8
	ghwcap = make([]C.uint32_t, size)

	// Make a slice pointing to the C array
	mapslice := (*[1 << 30]C.uint32_t)(unsafe.Pointer(&chwcap[0]))[:size:size]

	// And copy the C array into the Go array
	copy(ghwcap, mapslice)

	return
}

// KeyValueList represents a libxl_key_value_list.
//
// Represented as an empty struct for now, as there is no
// apparent need for this type to be exposed through the
// Go package.
type KeyValueList struct{}

func (kvl KeyValueList) fromC(ckvl *C.libxl_key_value_list) error      { return nil }
func (kvl KeyValueList) toC() (ckvl C.libxl_key_value_list, err error) { return }

// StringList represents a libxl_string_list.
type StringList []string

func (sl *StringList) fromC(csl *C.libxl_string_list) error {
	size := int(C.libxl_string_list_length(csl))
	list := (*[1 << 30]*C.char)(unsafe.Pointer(csl))[:size:size]

	*sl = make([]string, size)

	for i, v := range list {
		(*sl)[i] = C.GoString(v)
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
	cs := (*[1 << 30]C.uint8_t)(unsafe.Pointer(cbm._map))[:size:size]

	// And copy the C array into the Go array
	copy(bm.bitmap, cs)

	return nil
}

func (bm *Bitmap) toC() (C.libxl_bitmap, error) {
	var cbm C.libxl_bitmap

	size := len(bm.bitmap)
	cbm.size = C.uint32_t(size)
	cbm._map = (*C.uint8_t)(C.malloc(C.ulong(cbm.size) * C.sizeof_uint8_t))
	cs := (*[1 << 31]C.uint8_t)(unsafe.Pointer(cbm._map))[:size:size]

	copy(cs, bm.bitmap)

	return cbm, nil
}

/*
 * Types: IDL
 *
 * FIXME: Generate these automatically from the IDL
 */

type Physinfo struct {
	ThreadsPerCore    uint32
	CoresPerSocket    uint32
	MaxCpuId          uint32
	NrCpus            uint32
	CpuKhz            uint32
	TotalPages        uint64
	FreePages         uint64
	ScrubPages        uint64
	OutstandingPages  uint64
	SharingFreedPages uint64
	SharingUsedFrames uint64
	NrNodes           uint32
	HwCap             Hwcap
	CapHvm            bool
	CapHvmDirectio    bool
}

func (cphys *C.libxl_physinfo) toGo() (physinfo *Physinfo) {

	physinfo = &Physinfo{}
	physinfo.ThreadsPerCore = uint32(cphys.threads_per_core)
	physinfo.CoresPerSocket = uint32(cphys.cores_per_socket)
	physinfo.MaxCpuId = uint32(cphys.max_cpu_id)
	physinfo.NrCpus = uint32(cphys.nr_cpus)
	physinfo.CpuKhz = uint32(cphys.cpu_khz)
	physinfo.TotalPages = uint64(cphys.total_pages)
	physinfo.FreePages = uint64(cphys.free_pages)
	physinfo.ScrubPages = uint64(cphys.scrub_pages)
	physinfo.ScrubPages = uint64(cphys.scrub_pages)
	physinfo.SharingFreedPages = uint64(cphys.sharing_freed_pages)
	physinfo.SharingUsedFrames = uint64(cphys.sharing_used_frames)
	physinfo.NrNodes = uint32(cphys.nr_nodes)
	physinfo.HwCap = cphys.hw_cap.toGo()
	physinfo.CapHvm = bool(cphys.cap_hvm)
	physinfo.CapHvmDirectio = bool(cphys.cap_hvm_directio)

	return
}

type VersionInfo struct {
	XenVersionMajor int
	XenVersionMinor int
	XenVersionExtra string
	Compiler        string
	CompileBy       string
	CompileDomain   string
	CompileDate     string
	Capabilities    string
	Changeset       string
	VirtStart       uint64
	Pagesize        int
	Commandline     string
	BuildId         string
}

func (cinfo *C.libxl_version_info) toGo() (info *VersionInfo) {
	info = &VersionInfo{}
	info.XenVersionMajor = int(cinfo.xen_version_major)
	info.XenVersionMinor = int(cinfo.xen_version_minor)
	info.XenVersionExtra = C.GoString(cinfo.xen_version_extra)
	info.Compiler = C.GoString(cinfo.compiler)
	info.CompileBy = C.GoString(cinfo.compile_by)
	info.CompileDomain = C.GoString(cinfo.compile_domain)
	info.CompileDate = C.GoString(cinfo.compile_date)
	info.Capabilities = C.GoString(cinfo.capabilities)
	info.Changeset = C.GoString(cinfo.changeset)
	info.VirtStart = uint64(cinfo.virt_start)
	info.Pagesize = int(cinfo.pagesize)
	info.Commandline = C.GoString(cinfo.commandline)
	info.BuildId = C.GoString(cinfo.build_id)

	return
}

func (sr ShutdownReason) String() (str string) {
	cstr := C.libxl_shutdown_reason_to_string(C.libxl_shutdown_reason(sr))
	str = C.GoString(cstr)

	return
}

func (dt DomainType) String() (str string) {
	cstr := C.libxl_domain_type_to_string(C.libxl_domain_type(dt))
	str = C.GoString(cstr)

	return
}

type Dominfo struct {
	Uuid      Uuid
	Domid     Domid
	Ssidref   uint32
	SsidLabel string
	Running   bool
	Blocked   bool
	Paused    bool
	Shutdown  bool
	Dying     bool
	NeverStop bool

	ShutdownReason   int32
	OutstandingMemkb MemKB
	CurrentMemkb     MemKB
	SharedMemkb      MemKB
	PagedMemkb       MemKB
	MaxMemkb         MemKB
	CpuTime          time.Duration
	VcpuMaxId        uint32
	VcpuOnline       uint32
	Cpupool          uint32
	DomainType       int32
}

func (cdi *C.libxl_dominfo) toGo() (di *Dominfo) {

	di = &Dominfo{}
	di.Uuid = Uuid(cdi.uuid)
	di.Domid = Domid(cdi.domid)
	di.Ssidref = uint32(cdi.ssidref)
	di.SsidLabel = C.GoString(cdi.ssid_label)
	di.Running = bool(cdi.running)
	di.Blocked = bool(cdi.blocked)
	di.Paused = bool(cdi.paused)
	di.Shutdown = bool(cdi.shutdown)
	di.Dying = bool(cdi.dying)
	di.NeverStop = bool(cdi.never_stop)
	di.ShutdownReason = int32(cdi.shutdown_reason)
	di.OutstandingMemkb = MemKB(cdi.outstanding_memkb)
	di.CurrentMemkb = MemKB(cdi.current_memkb)
	di.SharedMemkb = MemKB(cdi.shared_memkb)
	di.PagedMemkb = MemKB(cdi.paged_memkb)
	di.MaxMemkb = MemKB(cdi.max_memkb)
	di.CpuTime = time.Duration(cdi.cpu_time)
	di.VcpuMaxId = uint32(cdi.vcpu_max_id)
	di.VcpuOnline = uint32(cdi.vcpu_online)
	di.Cpupool = uint32(cdi.cpupool)
	di.DomainType = int32(cdi.domain_type)

	return
}

// const char *libxl_scheduler_to_string(libxl_scheduler p);
func (s Scheduler) String() string {
	cs := C.libxl_scheduler_to_string(C.libxl_scheduler(s))
	// No need to free const return value

	return C.GoString(cs)
}

// int libxl_scheduler_from_string(const char *s, libxl_scheduler *e);
func (s *Scheduler) FromString(gstr string) (err error) {
	*s, err = SchedulerFromString(gstr)
	return
}

func SchedulerFromString(name string) (s Scheduler, err error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	var cs C.libxl_scheduler

	ret := C.libxl_scheduler_from_string(cname, &cs)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	s = Scheduler(cs)

	return
}

// libxl_cpupoolinfo = Struct("cpupoolinfo", [
//     ("poolid",      uint32),
//     ("pool_name",   string),
//     ("sched",       libxl_scheduler),
//     ("n_dom",       uint32),
//     ("cpumap",      libxl_bitmap)
//     ], dir=DIR_OUT)

type CpupoolInfo struct {
	Poolid      uint32
	PoolName    string
	Scheduler   Scheduler
	DomainCount int
	Cpumap      Bitmap
}

func (cci C.libxl_cpupoolinfo) toGo() (gci CpupoolInfo) {
	gci.Poolid = uint32(cci.poolid)
	gci.PoolName = C.GoString(cci.pool_name)
	gci.Scheduler = Scheduler(cci.sched)
	gci.DomainCount = int(cci.n_dom)
	gci.Cpumap.fromC(&cci.cpumap)

	return
}

// libxl_cpupoolinfo * libxl_list_cpupool(libxl_ctx*, int *nb_pool_out);
// void libxl_cpupoolinfo_list_free(libxl_cpupoolinfo *list, int nb_pool);
func (Ctx *Context) ListCpupool() (list []CpupoolInfo) {
	err := Ctx.CheckOpen()
	if err != nil {
		return
	}

	var nbPool C.int

	c_cpupool_list := C.libxl_list_cpupool(Ctx.ctx, &nbPool)

	defer C.libxl_cpupoolinfo_list_free(c_cpupool_list, nbPool)

	if int(nbPool) == 0 {
		return
	}

	// Magic
	cpupoolListSlice := (*[1 << 30]C.libxl_cpupoolinfo)(unsafe.Pointer(c_cpupool_list))[:nbPool:nbPool]
	for i := range cpupoolListSlice {
		info := cpupoolListSlice[i].toGo()
		list = append(list, info)
	}

	return
}

// int libxl_cpupool_info(libxl_ctx *ctx, libxl_cpupoolinfo *info, uint32_t poolid);
func (Ctx *Context) CpupoolInfo(Poolid uint32) (pool CpupoolInfo) {
	err := Ctx.CheckOpen()
	if err != nil {
		return
	}

	var c_cpupool C.libxl_cpupoolinfo

	ret := C.libxl_cpupool_info(Ctx.ctx, &c_cpupool, C.uint32_t(Poolid))
	if ret != 0 {
		err = Error(-ret)
		return
	}
	defer C.libxl_cpupoolinfo_dispose(&c_cpupool)

	pool = c_cpupool.toGo()

	return
}

// int libxl_cpupool_create(libxl_ctx *ctx, const char *name,
//                          libxl_scheduler sched,
//                          libxl_bitmap cpumap, libxl_uuid *uuid,
//                          uint32_t *poolid);
// FIXME: uuid
// FIXME: Setting poolid
func (Ctx *Context) CpupoolCreate(Name string, Scheduler Scheduler, Cpumap Bitmap) (err error, Poolid uint32) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

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

	ret := C.libxl_cpupool_create(Ctx.ctx, name, C.libxl_scheduler(Scheduler),
		cbm, &uuid, &poolid)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	Poolid = uint32(poolid)

	return
}

// int libxl_cpupool_destroy(libxl_ctx *ctx, uint32_t poolid);
func (Ctx *Context) CpupoolDestroy(Poolid uint32) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_cpupool_destroy(Ctx.ctx, C.uint32_t(Poolid))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuadd(libxl_ctx *ctx, uint32_t poolid, int cpu);
func (Ctx *Context) CpupoolCpuadd(Poolid uint32, Cpu int) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_cpupool_cpuadd(Ctx.ctx, C.uint32_t(Poolid), C.int(Cpu))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuadd_cpumap(libxl_ctx *ctx, uint32_t poolid,
//                                 const libxl_bitmap *cpumap);
func (Ctx *Context) CpupoolCpuaddCpumap(Poolid uint32, Cpumap Bitmap) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	cbm, err := Cpumap.toC()
	if err != nil {
		return
	}
	defer C.libxl_bitmap_dispose(&cbm)

	ret := C.libxl_cpupool_cpuadd_cpumap(Ctx.ctx, C.uint32_t(Poolid), &cbm)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuremove(libxl_ctx *ctx, uint32_t poolid, int cpu);
func (Ctx *Context) CpupoolCpuremove(Poolid uint32, Cpu int) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_cpupool_cpuremove(Ctx.ctx, C.uint32_t(Poolid), C.int(Cpu))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuremove_cpumap(libxl_ctx *ctx, uint32_t poolid,
//                                    const libxl_bitmap *cpumap);
func (Ctx *Context) CpupoolCpuremoveCpumap(Poolid uint32, Cpumap Bitmap) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	cbm, err := Cpumap.toC()
	if err != nil {
		return
	}
	defer C.libxl_bitmap_dispose(&cbm)

	ret := C.libxl_cpupool_cpuremove_cpumap(Ctx.ctx, C.uint32_t(Poolid), &cbm)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_rename(libxl_ctx *ctx, const char *name, uint32_t poolid);
func (Ctx *Context) CpupoolRename(Name string, Poolid uint32) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	name := C.CString(Name)
	defer C.free(unsafe.Pointer(name))

	ret := C.libxl_cpupool_rename(Ctx.ctx, name, C.uint32_t(Poolid))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

// int libxl_cpupool_cpuadd_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus);
func (Ctx *Context) CpupoolCpuaddNode(Poolid uint32, Node int) (Cpus int, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ccpus := C.int(0)

	ret := C.libxl_cpupool_cpuadd_node(Ctx.ctx, C.uint32_t(Poolid), C.int(Node), &ccpus)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	Cpus = int(ccpus)

	return
}

// int libxl_cpupool_cpuremove_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus);
func (Ctx *Context) CpupoolCpuremoveNode(Poolid uint32, Node int) (Cpus int, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ccpus := C.int(0)

	ret := C.libxl_cpupool_cpuremove_node(Ctx.ctx, C.uint32_t(Poolid), C.int(Node), &ccpus)
	if ret != 0 {
		err = Error(-ret)
		return
	}

	Cpus = int(ccpus)

	return
}

// int libxl_cpupool_movedomain(libxl_ctx *ctx, uint32_t poolid, uint32_t domid);
func (Ctx *Context) CpupoolMovedomain(Poolid uint32, Id Domid) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_cpupool_movedomain(Ctx.ctx, C.uint32_t(Poolid), C.uint32_t(Id))
	if ret != 0 {
		err = Error(-ret)
		return
	}

	return
}

//
// Utility functions
//
func (Ctx *Context) CpupoolFindByName(name string) (info CpupoolInfo, found bool) {
	plist := Ctx.ListCpupool()

	for i := range plist {
		if plist[i].PoolName == name {
			found = true
			info = plist[i]
			return
		}
	}
	return
}

func (Ctx *Context) CpupoolMakeFree(Cpumap Bitmap) (err error) {
	plist := Ctx.ListCpupool()

	for i := range plist {
		var Intersection Bitmap
		Intersection = Cpumap.And(plist[i].Cpumap)
		if !Intersection.IsEmpty() {
			err = Ctx.CpupoolCpuremoveCpumap(plist[i].Poolid, Intersection)
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

/*
 * Context
 */
var Ctx Context

func (Ctx *Context) IsOpen() bool {
	return Ctx.ctx != nil
}

func (Ctx *Context) Open() (err error) {
	if Ctx.ctx != nil {
		return
	}

	Ctx.logger = C.xtl_createlogger_stdiostream(C.stderr, C.XTL_ERROR, 0)
	if Ctx.logger == nil {
		err = fmt.Errorf("Cannot open stdiostream")
		return
	}

	ret := C.libxl_ctx_alloc(&Ctx.ctx, C.LIBXL_VERSION,
		0, (*C.xentoollog_logger)(unsafe.Pointer(Ctx.logger)))

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

func (Ctx *Context) Close() (err error) {
	ret := C.libxl_ctx_free(Ctx.ctx)
	Ctx.ctx = nil

	if ret != 0 {
		err = Error(-ret)
	}
	C.xtl_logger_destroy((*C.xentoollog_logger)(unsafe.Pointer(Ctx.logger)))
	return
}

func (Ctx *Context) CheckOpen() (err error) {
	if Ctx.ctx == nil {
		err = fmt.Errorf("Context not opened")
	}
	return
}

//int libxl_get_max_cpus(libxl_ctx *ctx);
func (Ctx *Context) GetMaxCpus() (maxCpus int, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_get_max_cpus(Ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	maxCpus = int(ret)
	return
}

//int libxl_get_online_cpus(libxl_ctx *ctx);
func (Ctx *Context) GetOnlineCpus() (onCpus int, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_get_online_cpus(Ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	onCpus = int(ret)
	return
}

//int libxl_get_max_nodes(libxl_ctx *ctx);
func (Ctx *Context) GetMaxNodes() (maxNodes int, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}
	ret := C.libxl_get_max_nodes(Ctx.ctx)
	if ret < 0 {
		err = Error(-ret)
		return
	}
	maxNodes = int(ret)
	return
}

//int libxl_get_free_memory(libxl_ctx *ctx, uint64_t *memkb);
func (Ctx *Context) GetFreeMemory() (memkb uint64, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}
	var cmem C.uint64_t
	ret := C.libxl_get_free_memory(Ctx.ctx, &cmem)

	if ret < 0 {
		err = Error(-ret)
		return
	}

	memkb = uint64(cmem)
	return

}

//int libxl_get_physinfo(libxl_ctx *ctx, libxl_physinfo *physinfo)
func (Ctx *Context) GetPhysinfo() (physinfo *Physinfo, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}
	var cphys C.libxl_physinfo
	C.libxl_physinfo_init(&cphys)
	defer C.libxl_physinfo_dispose(&cphys)

	ret := C.libxl_get_physinfo(Ctx.ctx, &cphys)

	if ret < 0 {
		err = Error(ret)
		return
	}
	physinfo = cphys.toGo()

	return
}

//const libxl_version_info* libxl_get_version_info(libxl_ctx *ctx);
func (Ctx *Context) GetVersionInfo() (info *VersionInfo, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	var cinfo *C.libxl_version_info

	cinfo = C.libxl_get_version_info(Ctx.ctx)

	info = cinfo.toGo()

	return
}

func (Ctx *Context) DomainInfo(Id Domid) (di *Dominfo, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	var cdi C.libxl_dominfo
	C.libxl_dominfo_init(&cdi)
	defer C.libxl_dominfo_dispose(&cdi)

	ret := C.libxl_domain_info(Ctx.ctx, &cdi, C.uint32_t(Id))

	if ret != 0 {
		err = Error(-ret)
		return
	}

	di = cdi.toGo()

	return
}

func (Ctx *Context) DomainUnpause(Id Domid) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_domain_unpause(Ctx.ctx, C.uint32_t(Id), nil)

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

//int libxl_domain_pause(libxl_ctx *ctx, uint32_t domain);
func (Ctx *Context) DomainPause(id Domid) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_domain_pause(Ctx.ctx, C.uint32_t(id), nil)

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

//int libxl_domain_shutdown(libxl_ctx *ctx, uint32_t domid);
func (Ctx *Context) DomainShutdown(id Domid) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_domain_shutdown(Ctx.ctx, C.uint32_t(id), nil)

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

//int libxl_domain_reboot(libxl_ctx *ctx, uint32_t domid);
func (Ctx *Context) DomainReboot(id Domid) (err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	ret := C.libxl_domain_reboot(Ctx.ctx, C.uint32_t(id), nil)

	if ret != 0 {
		err = Error(-ret)
	}
	return
}

//libxl_dominfo * libxl_list_domain(libxl_ctx*, int *nb_domain_out);
//void libxl_dominfo_list_free(libxl_dominfo *list, int nb_domain);
func (Ctx *Context) ListDomain() (glist []Dominfo) {
	err := Ctx.CheckOpen()
	if err != nil {
		return
	}

	var nbDomain C.int
	clist := C.libxl_list_domain(Ctx.ctx, &nbDomain)
	defer C.libxl_dominfo_list_free(clist, nbDomain)

	if int(nbDomain) == 0 {
		return
	}

	gslice := (*[1 << 30]C.libxl_dominfo)(unsafe.Pointer(clist))[:nbDomain:nbDomain]
	for i := range gslice {
		info := gslice[i].toGo()
		glist = append(glist, *info)
	}

	return
}

type Vcpuinfo struct {
	Vcpuid     uint32
	Cpu        uint32
	Online     bool
	Blocked    bool
	Running    bool
	VCpuTime   time.Duration
	Cpumap     Bitmap
	CpumapSoft Bitmap
}

func (cvci C.libxl_vcpuinfo) toGo() (gvci Vcpuinfo) {
	gvci.Vcpuid = uint32(cvci.vcpuid)
	gvci.Cpu = uint32(cvci.cpu)
	gvci.Online = bool(cvci.online)
	gvci.Blocked = bool(cvci.blocked)
	gvci.Running = bool(cvci.running)
	gvci.VCpuTime = time.Duration(cvci.vcpu_time)
	gvci.Cpumap.fromC(&cvci.cpumap)
	gvci.CpumapSoft.fromC(&cvci.cpumap_soft)

	return
}

//libxl_vcpuinfo *libxl_list_vcpu(libxl_ctx *ctx, uint32_t domid,
//				int *nb_vcpu, int *nr_cpus_out);
//void libxl_vcpuinfo_list_free(libxl_vcpuinfo *, int nr_vcpus);
func (Ctx *Context) ListVcpu(id Domid) (glist []Vcpuinfo) {
	err := Ctx.CheckOpen()
	if err != nil {
		return
	}

	var nbVcpu C.int
	var nrCpu C.int

	clist := C.libxl_list_vcpu(Ctx.ctx, C.uint32_t(id), &nbVcpu, &nrCpu)
	defer C.libxl_vcpuinfo_list_free(clist, nbVcpu)

	if int(nbVcpu) == 0 {
		return
	}

	gslice := (*[1 << 30]C.libxl_vcpuinfo)(unsafe.Pointer(clist))[:nbVcpu:nbVcpu]
	for i := range gslice {
		info := gslice[i].toGo()
		glist = append(glist, info)
	}

	return
}

func (ct ConsoleType) String() (str string) {
	cstr := C.libxl_console_type_to_string(C.libxl_console_type(ct))
	str = C.GoString(cstr)

	return
}

//int libxl_console_get_tty(libxl_ctx *ctx, uint32_t domid, int cons_num,
//libxl_console_type type, char **path);
func (Ctx *Context) ConsoleGetTty(id Domid, consNum int, conType ConsoleType) (path string, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	var cpath *C.char
	ret := C.libxl_console_get_tty(Ctx.ctx, C.uint32_t(id), C.int(consNum), C.libxl_console_type(conType), &cpath)
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
func (Ctx *Context) PrimaryConsoleGetTty(domid uint32) (path string, err error) {
	err = Ctx.CheckOpen()
	if err != nil {
		return
	}

	var cpath *C.char
	ret := C.libxl_primary_console_get_tty(Ctx.ctx, C.uint32_t(domid), &cpath)
	if ret != 0 {
		err = Error(-ret)
		return
	}
	defer C.free(unsafe.Pointer(cpath))

	path = C.GoString(cpath)
	return
}
