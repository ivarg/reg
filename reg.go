// Package reg implements a simplified interface to the Windows Registry.
//
// A registry key is obtained by opening it, and each subsequent call will result in corresponding
// requests to the registry.
package reg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"unsafe"
)

type RegKey syscall.Handle

var (
	regEnumValueP, regSetValueExP *syscall.Proc
)

func init() {
	dll := syscall.MustLoadDLL("advapi32.dll")
	regEnumValueP = dll.MustFindProc("RegEnumValueW")
	regSetValueExP = dll.MustFindProc("RegSetValueExW")
}

func OpenRegKey(path string, root RegKey) (RegKey, error) {
	var key syscall.Handle
	ps, _ := syscall.UTF16PtrFromString(path)
	if err := syscall.RegOpenKeyEx(syscall.Handle(root), ps, 0, syscall.KEY_READ|syscall.KEY_SET_VALUE, &key); err != nil {
		//if err := syscall.RegOpenKeyEx(syscall.Handle(root), ps, 0, syscall.KEY_READ, &key); err != nil {
		return RegKey(0), err
	}

	return RegKey(key), nil
}

func (k RegKey) Close() {
	syscall.RegCloseKey(syscall.Handle(k))
}

func (k RegKey) SubKeys() []string {
	var nkeys, nvals uint32
	if err := syscall.RegQueryInfoKey(syscall.Handle(k), nil, nil, nil, &nkeys, nil, nil, &nvals, nil, nil, nil, nil); err != nil {
		panic(err)
	}

	var subkeys []string
	var buf [1 << 10]uint16
	for i := uint32(0); i < nkeys; i++ {
		blen := uint32(len(buf))
		if err := syscall.RegEnumKeyEx(syscall.Handle(k), i, &buf[0], &blen, nil, nil, nil, nil); err != nil {
			panic(err)
		}
		k := syscall.UTF16ToString(buf[:])
		subkeys = append(subkeys, k)
	}
	return subkeys
}

func (k RegKey) DWordValue(key string) (uint32, error) {
	d, typ, err := k.regValue(key)
	if err != nil {
		return 0, err
	}
	if typ != syscall.REG_DWORD {
		return 0, fmt.Errorf("Registry key not a DWORD")
	}
	var val uint32
	buf := bytes.NewReader(d)
	if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
		return 0, err
	}
	return val, nil
}

func (k RegKey) SetDWordValue(name string, val uint32) error {
	uname, _ := syscall.UTF16PtrFromString(name)
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, val); err != nil {
		return err
	}

	if ret, _, _ := regSetValueExP.Call(
		uintptr(k),
		uintptr(unsafe.Pointer(uname)),
		0,
		uintptr(syscall.REG_DWORD),
		uintptr(unsafe.Pointer(&buf.Bytes()[0])),
		uintptr(buf.Len()),
	); ret != 0 {
		return fmt.Errorf("SetDWordValue error: %d", ret)
	}

	return nil
}

func (k RegKey) BoolValue(key string) (bool, error) {
	d, t, err := k.regValue(key)
	if err != nil {
		return false, err
	}
	if t != syscall.REG_DWORD {
		return false, fmt.Errorf("Registry key not a DWORD")
	}
	val, n := binary.Uvarint(d)
	if n < 0 || val > 1 {
		return false, fmt.Errorf("Value not a bool")
	}
	return val == 1, nil
}

func (k RegKey) StringValue(key string) (string, error) {
	d, t, err := k.regValue(key)
	if err != nil {
		return "", err
	}
	if t != syscall.REG_SZ {
		return "", fmt.Errorf("Registry key not a string")
	}
	buf := (*[1 << 10]uint16)(unsafe.Pointer(&d[0]))[:]
	return syscall.UTF16ToString(buf), nil
}

func (k RegKey) Values() map[string]string {
	var nkeys, nvals uint32
	if err := syscall.RegQueryInfoKey(syscall.Handle(k), nil, nil, nil, &nkeys, nil, nil, &nvals, nil, nil, nil, nil); err != nil {
		log.Fatal(err)
	}

	var values = make(map[string]string, nvals)
	var buf [1 << 10]uint16
	var data [1 << 10]byte
	for i := uint32(0); i < nvals; i++ {
		var typ uint32
		blen := uint32(len(buf))
		dlen := uint32(len(data))
		if err := myRegEnumValue(syscall.Handle(k), i, &buf[0], &blen, &typ, &data[0], &dlen); err != nil {
			panic(err)
		}
		valName := syscall.UTF16ToString(buf[:blen])
		switch typ {
		case syscall.REG_SZ:
			values[valName] = "string"
		case syscall.REG_DWORD:
			values[valName] = "uint32"
		case syscall.REG_BINARY:
			values[valName] = "binary"
		}
	}
	return values
}

func (k RegKey) regValue(key string) ([]byte, uint32, error) {
	kname, _ := syscall.UTF16PtrFromString(key)
	var typ uint32
	var data [1 << 10]byte
	dlen := uint32(len(data))
	if err := syscall.RegQueryValueEx(syscall.Handle(k), kname, nil, &typ, &data[0], &dlen); err != nil {
		return nil, 0, err
	}
	return data[:dlen], typ, nil
}

func myRegEnumValue(hKey syscall.Handle, index uint32, lpValueName *uint16, lpcchValueName *uint32, lpType *uint32, lpData *byte, lpcbData *uint32) error {
	ret, _, err := regEnumValueP.Call(uintptr(hKey), uintptr(index),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(unsafe.Pointer(lpcchValueName)),
		0,
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)))
	if ret != 0 {
		return err
	}
	return nil
}
