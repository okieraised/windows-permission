package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32DLL                   = windows.NewLazyDLL("Advapi32.dll")
	procLsaOpenPolicy             = advapi32DLL.NewProc("LsaOpenPolicy")
	procLsaQueryInformationPolicy = advapi32DLL.NewProc("LsaQueryInformationPolicy")
	procAuditQuerySystemPolicy    = advapi32DLL.NewProc("AuditQuerySystemPolicy")
	procAuditSetSystemPolicy      = advapi32DLL.NewProc("AuditSetSystemPolicy")
)

const (
	ObjectAcess     string = "{6997984a-797a-11d9-bed3-505054503030}"
	SubObjectAccess string = "{0cce921d-69ae-11d9-bed3-505054503030}"
)

const (
	POLICY_VIEW_LOCAL_INFORMATION   = 0x0001
	POLICY_VIEW_AUDIT_INFORMATION   = 0x0002
	POLICY_GET_PRIVATE_INFORMATION  = 0x0004
	POLICY_TRUST_ADMIN              = 0x0008
	POLICY_CREATE_ACCOUNT           = 0x0010
	POLICY_CREATE_SECRET            = 0x0020
	POLICY_CREATE_PRIVILEGE         = 0x0040
	POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x0080
	POLICY_SET_AUDIT_REQUIREMENTS   = 0x0100
	POLICY_AUDIT_LOG_ADMIN          = 0x0200
	POLICY_SERVER_ADMIN             = 0x0400
	POLICY_LOOKUP_NAMES             = 0x0800
	POLICY_ALL_ACCESS               = windows.STANDARD_RIGHTS_REQUIRED | POLICY_VIEW_LOCAL_INFORMATION | POLICY_VIEW_AUDIT_INFORMATION | POLICY_GET_PRIVATE_INFORMATION | POLICY_TRUST_ADMIN | POLICY_CREATE_ACCOUNT | POLICY_CREATE_SECRET | POLICY_CREATE_PRIVILEGE | POLICY_SET_DEFAULT_QUOTA_LIMITS | POLICY_SET_AUDIT_REQUIREMENTS | POLICY_AUDIT_LOG_ADMIN | POLICY_SERVER_ADMIN | POLICY_LOOKUP_NAMES
)

const (
	POLICY_AUDIT_EVENT_UNCHANGED = 0x00000000
	POLICY_AUDIT_EVENT_SUCCESS   = 0x00000001
	POLICY_AUDIT_EVENT_FAILURE   = 0x00000002
	POLICY_AUDIT_EVENT_NONE      = 0x00000004
)

const (
	PolicyAuditLogInformation = iota
	PolicyAuditEventsInformation
	PolicyPrimaryDomainInformation
	PolicyPdAccountInformation
	PolicyAccountDomainInformation
	PolicyLsaServerRoleInformation
	PolicyReplicaSourceInformation
	PolicyDefaultQuotaInformation
	PolicyModificationInformation
	PolicyAuditFullSetInformation
	PolicyAuditFullQueryInformation
	PolicyDnsDomainInformation
	PolicyDnsDomainInformationInt
	PolicyLocalAccountDomainInformation
	PolicyMachineAccountInformation
	PolicyLastEntry
)

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               *UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type POLICY_AUDIT_EVENTS_INFO struct {
	AuditingMode           bool
	EventAuditingOptions   []uint32
	MaximumAuditEventCount uint32
}

type AUDIT_POLICY_INFORMATION struct {
	AuditSubCategoryGuid windows.GUID
	AuditingInformation  uint32
	AuditCategoryGuid    windows.GUID
}

func main() {
	token := windows.GetCurrentProcessToken()

	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token)
	fmt.Println(err)

	fmt.Println("Token: ", token)

	tp := windows.Tokenprivileges{}

	privilege, _ := syscall.UTF16PtrFromString("SeSecurityPrivilege")

	err = windows.LookupPrivilegeValue(nil,
		privilege,
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
	fmt.Printf("Error: %v\n", err)

	guid, _ := windows.GUIDFromString(ObjectAcess)
	subGUID, _ := windows.GUIDFromString(SubObjectAccess)
	fmt.Println(guid, subGUID)
	// guidArr := []windows.GUID{subGUID}

	// result := AUDIT_POLICY_INFORMATION{}

	// status, _, err := procAuditQuerySystemPolicy.Call(
	// 	uintptr(unsafe.Pointer(&subGUID)),
	// 	1,
	// 	uintptr(unsafe.Pointer(&result)))

	// fmt.Printf("Error: %v\n", err)
	// fmt.Println(status)

	// fmt.Println(result)

	toSet := []AUDIT_POLICY_INFORMATION{
		{
			AuditSubCategoryGuid: subGUID,
			AuditCategoryGuid:    guid,
			AuditingInformation:  POLICY_AUDIT_EVENT_FAILURE,
		},
		{
			AuditSubCategoryGuid: subGUID,
			AuditCategoryGuid:    guid,
			AuditingInformation:  POLICY_AUDIT_EVENT_SUCCESS,
		},
	}

	status2, _, err := procAuditSetSystemPolicy.Call(
		uintptr(unsafe.Pointer(&toSet[0])),
		1)

	fmt.Printf("Error: %v\n", err)
	fmt.Println(status2)

	// token := windows.GetCurrentProcessToken()

	// err := windows.OpenProcessToken(windows.CurrentProcess(),
	// 	windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
	// 	&token)
	// fmt.Println(err)

	// fmt.Println("Token: ", token)

	// tp := windows.Tokenprivileges{}

	// privilege, _ := syscall.UTF16PtrFromString("SeAuditPrivilege")

	// err = windows.LookupPrivilegeValue(nil,
	// 	privilege,
	// 	&(tp.Privileges[0].Luid))
	// fmt.Println(err)
	// var handle windows.Handle

	// uniStr := UNICODE_STRING{}
	// uniStr.Buffer = 0
	// uniStr.Length = 0
	// uniStr.MaximumLength = 0

	// attribute := OBJECT_ATTRIBUTES{}
	// attribute.Length = 0
	// attribute.Attributes = 0
	// attribute.SecurityQualityOfService = 0
	// attribute.SecurityDescriptor = 0
	// attribute.RootDirectory = handle
	// attribute.ObjectName = &uniStr

	// status, _, err := procLsaOpenPolicy.Call(
	// 	uintptr(unsafe.Pointer(&uniStr)),
	// 	uintptr(unsafe.Pointer(&attribute)),
	// 	uintptr(POLICY_VIEW_AUDIT_INFORMATION),
	// 	uintptr(unsafe.Pointer(&handle)))

	// fmt.Printf("Error: %v\n", err)
	// fmt.Println(status)

	// var auditInfo POLICY_AUDIT_EVENTS_INFO

	// status, _, err = procLsaQueryInformationPolicy.Call(status,
	// 	uintptr(PolicyAuditEventsInformation),
	// 	uintptr(unsafe.Pointer(&auditInfo)))
	// fmt.Printf("Error: %v\n", err)
	// fmt.Println(status)
	// fmt.Println(auditInfo)

}

// func main() {
// 	folderName := `C:\Users\Spc.Pham\Desktop\test`
// 	sidStr := "S-1-1-0"
// 	//   S-1-5-21-464891705-125813295-3647906382-1001 S-1-1-0 S-1-5-32-544

// 	windows.TrusteeValueFromString("Everyone")

// 	token := windows.GetCurrentProcessToken()

// 	err := windows.OpenProcessToken(windows.CurrentProcess(),
// 		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
// 		&token)
// 	fmt.Println(err)

// 	fmt.Println("Token: ", token)

// 	tp := windows.Tokenprivileges{}

// 	err = windows.LookupPrivilegeValue(nil,
// 		syscall.StringToUTF16Ptr("SeSecurityPrivilege"),
// 		&(tp.Privileges[0].Luid))
// 	fmt.Println(err)

// 	fmt.Println("LookupPrivilegeValue luid: ", tp.Privileges[0].Luid)

// 	luidAttr := windows.LUIDAndAttributes{
// 		Luid:       tp.Privileges[0].Luid,
// 		Attributes: windows.SE_PRIVILEGE_ENABLED,
// 	}

// 	tp.PrivilegeCount = 1
// 	tp.Privileges = [1]windows.LUIDAndAttributes{luidAttr}
// 	fmt.Println("tp: ", tp)

// 	err = windows.AdjustTokenPrivileges(token,
// 		false,
// 		&tp,
// 		0,
// 		nil,
// 		nil)

// 	fmt.Println("AdjustTokenPrivileges error: ", err)

// 	sid, err := windows.StringToSid(sidStr)
// 	fmt.Println("sid error: ", err)
// 	fmt.Println("SID: ", sid)
// 	trustee := windows.TrusteeValueFromSID(sid)

// 	winTrustee := windows.TRUSTEE{
// 		MultipleTrustee:          nil,
// 		MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
// 		TrusteeForm:              windows.TRUSTEE_IS_SID,
// 		TrusteeType:              windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
// 		TrusteeValue:             trustee,
// 	}

// 	fmt.Println("winTrustee: ", winTrustee)

// 	result, err := windows.GetNamedSecurityInfo(folderName,
// 		windows.SE_FILE_OBJECT,
// 		windows.SACL_SECURITY_INFORMATION)
// 	fmt.Println("GetNamedSecurityInfo() err: ", err)
// 	fmt.Println("GetNamedSecurityInfo(): ", result)

// 	ea := windows.EXPLICIT_ACCESS{
// 		AccessPermissions: windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF,
// 		AccessMode:        windows.SET_AUDIT_SUCCESS,
// 		Inheritance:       windows.CONTAINER_INHERIT_ACE | windows.OBJECT_INHERIT_ACE,
// 		Trustee:           winTrustee,
// 	}

// 	eaArr := []windows.EXPLICIT_ACCESS{ea}

// 	sacl, err := windows.ACLFromEntries(eaArr, nil)
// 	fmt.Println("ACLFromEntries err: ", err)
// 	fmt.Println("SACL: ", sacl)

// 	err = windows.SetNamedSecurityInfo(folderName,
// 		windows.SE_FILE_OBJECT,
// 		windows.SACL_SECURITY_INFORMATION,
// 		sid,
// 		nil,
// 		nil,
// 		sacl)
// 	fmt.Println("SetNamedSecurityInfo() err: ", err)

// }

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
