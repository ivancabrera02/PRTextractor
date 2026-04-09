# PRTextractor

## ¿Qué es PRTextractor?

**PRTextractor** es una herramienta escrita en Go para Windows que extrae el **PRT cookie** (`x-ms-RefreshTokenCredential`) de dispositivos unidos a **Microsoft Entra ID (Azure AD)**. Este cookie puede utilizarse en ejercicios de pentesting para obtener tokens de acceso de Azure sin conocer las credenciales del usuario, siempre dentro de un entorno autorizado.

### ¿Qué es el PRT?

El **Primary Refresh Token (PRT)** es una credencial especial que Windows almacena en dispositivos unidos a Entra ID. Permite a los usuarios acceder a recursos de Microsoft 365 y Azure de forma transparente (Single Sign-On). En ejercicios de Red Team, la extracción del PRT cookie puede permitir la suplantación de sesiones de usuario sin necesidad de phishing ni credenciales.

---

## ¿Cómo funciona?

PRTextractor sigue el flujo estándar que usa el propio sistema operativo Windows:

```
[1] Leer registro de Windows
        └─> HKLM\SYSTEM\...\CloudDomainJoin\JoinInfo  →  TenantID + DeviceID
        └─> HKLM\SOFTWARE\...\AAD\Package             →  TpmProtected

[2] Obtener Nonce
        └─> POST https://login.microsoftonline.com/<TenantID>/oauth2/token
            body: grant_type=srv_challenge

[3] Llamada COM a IProofOfPossessionCookieInfoManager
        └─> GetCookieInfoForUri(login.microsoftonline.com/...?sso_nonce=<nonce>)
            └─> Devuelve la cookie: x-ms-RefreshTokenCredential

[4] Output en formato JSON (compatible con EditThisCookie / Burp Suite)
```

## Uso del cookie extraído

El JSON generado es compatible con extensiones de gestión de cookies para navegadores como **EditThisCookie** o **Cookie-Editor**. Para usarlo en un ejercicio de pentesting:

1. Ejecuta PRTextractor en el dispositivo objetivo.
2. Copia el JSON resultante.
3. En tu navegador, abre una pestaña en `https://login.microsoftonline.com`.
4. Importa el cookie mediante la extensión de gestión de cookies.
5. Accede a `https://portal.azure.com` o `https://myapps.microsoft.com` deberías obtener una sesión autenticada como el usuario del dispositivo.

## Técnica

PRTextractor abusa del flujo legítimo de SSO de Windows:

- **`IProofOfPossessionCookieInfoManager`** es una interfaz COM documentada por Microsoft que usan navegadores como Edge para obtener cookies de SSO automáticamente. PRTextractor invoca esta interfaz directamente.
- La comunicación con `login.microsoftonline.com` para obtener el nonce se realiza a través de **WinHTTP** (sin dependencias externas de red).
- No se realiza ninguna inyección de código, volcado de LSASS ni manipulación del kernel.

### Referencias
- [Abusing Azure AD SSO with the Primary Refresh Token - dirkjanm.io](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
- [MS-OAPXBC: OAuth 2.0 Protocol Extensions - Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/)
- [IProofOfPossessionCookieInfoManager - Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/proofofpossessioncookieinfo/)
