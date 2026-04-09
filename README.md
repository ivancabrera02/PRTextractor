# PRTextractor

## What is PRTextractor?

**PRTextractor** is a Go-based tool for Windows that extracts the **PRT cookie** (`x-ms-RefreshTokenCredential`) from devices joined to **Microsoft Entra ID (Azure AD)**. This cookie can be used in pentesting exercises to obtain Azure access tokens without knowing the user's credentials, always within an authorized environment.

### What is the PRT?

The **Primary Refresh Token (PRT)** is a special credential that Windows stores on Entra ID-joined devices. It allows users to seamlessly access Microsoft 365 and Azure resources (Single Sign-On). In Red Team exercises, extracting the PRT cookie can allow session impersonation without needing phishing or credentials.

## How does it work?

PRTextractor follows the standard flow used by the Windows OS itself:

```
[1] Read Windows Registry
        └─> HKLM\SYSTEM\...\CloudDomainJoin\JoinInfo  →  TenantID + DeviceID
        └─> HKLM\SOFTWARE\...\AAD\Package             →  TpmProtected

[2] Obtain Nonce
        └─> POST https://login.microsoftonline.com/<TenantID>/oauth2/token
            body: grant_type=srv_challenge

[3] COM call to IProofOfPossessionCookieInfoManager
        └─> GetCookieInfoForUri(login.microsoftonline.com/...?sso_nonce=<nonce>)
            └─> Returns the cookie: x-ms-RefreshTokenCredential

[4] Output in JSON format (compatible with EditThisCookie / Burp Suite)
```

## Using the extracted cookie

The generated JSON is compatible with browser cookie management extensions such as **EditThisCookie** or **Cookie-Editor**. To use it in a pentesting exercise:

1. Run PRTextractor on the target device.
2. Copy the resulting JSON.
3. In your browser, open a tab at `https://login.microsoftonline.com`.
4. Import the cookie using your cookie management extension.
5. Navigate to `https://portal.azure.com` or `https://myapps.microsoft.com` — you should get an authenticated session as the device's user.

## Technique

PRTextractor abuses the legitimate Windows SSO flow:

- **`IProofOfPossessionCookieInfoManager`** is a COM interface documented by Microsoft, used by browsers like Edge to automatically obtain SSO cookies. PRTextractor invokes this interface directly.
- Communication with `login.microsoftonline.com` to obtain the nonce is done via **WinHTTP** (no external network dependencies).
- No code injection, LSASS dumping, or kernel manipulation is performed.

### References
- [Abusing Azure AD SSO with the Primary Refresh Token - dirkjanm.io](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
- [MS-OAPXBC: OAuth 2.0 Protocol Extensions - Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/)
- [IProofOfPossessionCookieInfoManager - Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/proofofpossessioncookieinfo/)
