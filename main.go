package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)
// https://devblogs.microsoft.com/oldnewthing/20170310-00/?p=95705
func main() {
	folderName := `C:\Users\Spc.Pham\Desktop\test`
	sidStr := "S-1-1-0"
	//   S-1-5-21-464891705-125813295-3647906382-1001 S-1-1-0 S-1-5-32-544

	windows.TrusteeValueFromString("Everyone")

	token := windows.GetCurrentProcessToken()

	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token)
	fmt.Println(err)

	fmt.Println("Token: ", token)

	tp := windows.Tokenprivileges{}

	err = windows.LookupPrivilegeValue(nil,
		syscall.StringToUTF16Ptr("SeSecurityPrivilege"),
		&(tp.Privileges[0].Luid))
	fmt.Println(err)

	fmt.Println("LookupPrivilegeValue luid: ", tp.Privileges[0].Luid)

	luidAttr := windows.LUIDAndAttributes{
		Luid:       tp.Privileges[0].Luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}

	tp.PrivilegeCount = 1
	tp.Privileges = [1]windows.LUIDAndAttributes{luidAttr}
	fmt.Println("tp: ", tp)

	err = windows.AdjustTokenPrivileges(token,
		false,
		&tp,
		0,
		nil,
		nil)

	fmt.Println("AdjustTokenPrivileges error: ", err)

	sid, err := windows.StringToSid(sidStr)
	fmt.Println("sid error: ", err)
	fmt.Println("SID: ", sid)
	trustee := windows.TrusteeValueFromSID(sid)

	winTrustee := windows.TRUSTEE{
		MultipleTrustee:          nil,
		MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
		TrusteeForm:              windows.TRUSTEE_IS_SID,
		TrusteeType:              windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
		TrusteeValue:             trustee,
	}

	fmt.Println("winTrustee: ", winTrustee)

	result, err := windows.GetNamedSecurityInfo(folderName,
		windows.SE_FILE_OBJECT,
		windows.SACL_SECURITY_INFORMATION)
	fmt.Println("GetNamedSecurityInfo() err: ", err)
	fmt.Println("GetNamedSecurityInfo(): ", result)

	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF,
		AccessMode:        windows.SET_AUDIT_SUCCESS,
		Inheritance:       windows.CONTAINER_INHERIT_ACE | windows.OBJECT_INHERIT_ACE,
		Trustee:           winTrustee,
	}

	eaArr := []windows.EXPLICIT_ACCESS{ea}

	sacl, err := windows.ACLFromEntries(eaArr, nil)
	fmt.Println("ACLFromEntries err: ", err)
	fmt.Println("SACL: ", sacl)

	err = windows.SetNamedSecurityInfo(folderName,
		windows.SE_FILE_OBJECT,
		windows.SACL_SECURITY_INFORMATION,
		sid,
		nil,
		nil,
		sacl)
	fmt.Println("SetNamedSecurityInfo() err: ", err)

}

// package main

// import (
// 	"fmt"
// 	"syscall"
// 	"unsafe"
// )

// // error is nil on success
// func reboot() error {

// 	user32 := syscall.MustLoadDLL("user32")
// 	defer user32.Release()

// 	kernel32 := syscall.MustLoadDLL("kernel32")
// 	defer user32.Release()

// 	advapi32 := syscall.MustLoadDLL("advapi32")
// 	defer advapi32.Release()

// 	// ExitWindowsEx := user32.MustFindProc("ExitWindowsEx")
// 	GetCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")
// 	GetLastError := kernel32.MustFindProc("GetLastError")
// 	OpenProdcessToken := advapi32.MustFindProc("OpenProcessToken")
// 	LookupPrivilegeValue := advapi32.MustFindProc("LookupPrivilegeValueW")
// 	AdjustTokenPrivileges := advapi32.MustFindProc("AdjustTokenPrivileges")

// 	currentProcess, _, _ := GetCurrentProcess.Call()

// 	const tokenAdjustPrivileges = 0x0020
// 	const tokenQuery = 0x0008
// 	var hToken uintptr

// 	result, _, err := OpenProdcessToken.Call(currentProcess, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&hToken)))
// 	if result != 1 {
// 		fmt.Println("OpenProcessToken(): ", result, " err: ", err)
// 		return err
// 	}
// 	fmt.Println("hToken: ", hToken)

// 	const SeShutdownName = "SeSecurityPrivilege"

// 	type Luid struct {
// 		lowPart  uint32 // DWORD
// 		highPart int32  // long
// 	}
// 	type LuidAndAttributes struct {
// 		luid       Luid   // LUID
// 		attributes uint32 // DWORD
// 	}

// 	type TokenPrivileges struct {
// 		privilegeCount uint32 // DWORD
// 		privileges     [1]LuidAndAttributes
// 	}

// 	var tkp TokenPrivileges

// 	result, _, err = LookupPrivilegeValue.Call(uintptr(0), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SeShutdownName))), uintptr(unsafe.Pointer(&(tkp.privileges[0].luid))))
// 	if result != 1 {
// 		fmt.Println("LookupPrivilegeValue(): ", result, " err: ", err)
// 		return err
// 	}
// 	fmt.Println("LookupPrivilegeValue luid: ", tkp.privileges[0].luid)

// 	const SePrivilegeEnabled uint32 = 0x00000002

// 	tkp.privilegeCount = 1
// 	tkp.privileges[0].attributes = SePrivilegeEnabled

// 	result, _, err = AdjustTokenPrivileges.Call(hToken, 0, uintptr(unsafe.Pointer(&tkp)), 0, uintptr(0), 0)
// 	if result != 1 {
// 		fmt.Println("AdjustTokenPrivileges() ", result, " err: ", err)
// 		return err
// 	}

// 	result, _, _ = GetLastError.Call()
// 	if result != 0 {
// 		fmt.Println("GetLastError() ", result)
// 		return err
// 	}

// 	const ewxForceIfHung = 0x00000010
// 	const ewxReboot = 0x00000002
// 	const ewxShutdown = 0x00000001
// 	const shutdownReasonMajorSoftware = 0x00030000

// 	// result, _, err = ExitWindowsEx.Call(ewxShutdown|ewxForceIfHung, shutdownReasonMajorSoftware)
// 	// if result != 1 {
// 	// 	fmt.Println("Failed to initiate reboot:", err)
// 	// 	return err
// 	// }

// 	return nil
// }

// func main() {
// 	err := reboot()
// 	if err != nil {
// 		fmt.Println("Failed to initiate reboot:", err)
// 	}
// }
