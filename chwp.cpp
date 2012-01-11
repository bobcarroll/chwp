// chwp.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

BOOL GetUserSid(HANDLE, PSID*);
int EnablePriv(LPCWSTR);
BOOL GrantDaclPermissions(HANDLE, PSID, ACCESS_MASK);
BOOL GetOwnerLogonName(HANDLE, wchar_t**, wchar_t**);

int _tmain(int argc, _TCHAR* argv[])
{
	HWINSTA hws;
	DWORD wssz = 0;
	wchar_t *pwsname;
	HANDLE hselftok = NULL;
	PSID pselfsid = NULL;
	HDESK hdesktop;
	HWND hpmwnd;
	DWORD dwpmproc = 0;
	HANDLE hpmproc;
	HANDLE hpmtok = NULL;
	HANDLE hnewtok = NULL;
	SECURITY_DESCRIPTOR *psd = NULL;
	DWORD dwsdsz = 0;
	wchar_t *logonname;
	wchar_t *domain;
	
	if (argc != 2) {
		wprintf(L"USAGE: chwp.exe <bitmap file>\n");
		return 0;
	}

	
	/* get the current logon SID */

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hselftok)) {
		wprintf(L"Failed to obtain current process token (%d)\n", GetLastError());
		return 1;
	}

	if (!GetUserSid(hselftok, &pselfsid)) {
		wprintf(L"Failed to get the current logon SID (%d)\n", GetLastError());

		CloseHandle(hselftok);

		return 1;
	}

	CloseHandle(hselftok);


	/* attach to the interactive desktop if we're not already there */

	hws = GetProcessWindowStation();
	GetUserObjectInformationW(hws, UOI_NAME, NULL, 0, &wssz);

	pwsname = (wchar_t*)malloc(wssz + 1);
	memset(pwsname, 0, wssz + 1);

	GetUserObjectInformationW(hws, UOI_NAME, pwsname, wssz, NULL);
	wprintf(L"Current window station is %s\n", pwsname);
	
	if (wcscmp(pwsname, L"WinSta0") != 0) {
		wprintf(L"Attaching current process to WinSta0\n", pwsname);

		free(pwsname);
		CloseWindowStation(hws);

		hws = OpenWindowStation(L"WinSta0", FALSE, READ_CONTROL | WRITE_DAC);
		if (hws == NULL) {
			wprintf(L"Failed to re-open WinSta0 for WRITE_DAC (%d)\n", GetLastError());
			
			free(pselfsid);
			
			return 1;
		}

		if (!GrantDaclPermissions(hws, pselfsid, WINSTA_ALL_ACCESS)) {
			wprintf(L"Failed to adjust DACL on WinSta0 (%d)\n", GetLastError());

			free(pselfsid);
			CloseWindowStation(hws);

			return 1;
		}

		CloseWindowStation(hws);

		hws = OpenWindowStation(L"WinSta0", FALSE, WINSTA_ALL_ACCESS);
		if (hws == NULL) {
			wprintf(L"Failed to re-open WinSta0 for all access (%d)\n", GetLastError());

			free(pselfsid);

			return 1;
		}

		if (!SetProcessWindowStation(hws)) {
			wprintf(L"Failed to attach current process to WinSta0 (%d)\n", GetLastError());

			free(pselfsid);
			CloseWindowStation(hws);

			return 1;
		}

		CloseWindowStation(hws);
		hws = GetProcessWindowStation();

		hdesktop = OpenDesktop(L"Default", 0, FALSE, GENERIC_READ);
		if (hdesktop == NULL) {
			wprintf(L"Failed to open the default desktop for reading (%d)\n", GetLastError());

			free(pselfsid);
			CloseWindowStation(hws);
			
			return 1;
		}

		if (!SetThreadDesktop(hdesktop)) {
			wprintf(L"Failed to attached current thread to the default desktop (%d)\n", GetLastError());
			
			free(pselfsid);
			CloseDesktop(hdesktop);
			CloseWindowStation(hws);
			
			return 1;
		}
		
		CloseDesktop(hdesktop);
		CloseWindowStation(hws);

		wprintf(L"Current process is now attached to WinSta0\\Default\n");
	} else {
		free(pwsname);
		CloseWindowStation(hws);
	}


	/* find the console user's explorer.exe process */

	hpmwnd = FindWindow(L"Progman", L"Program Manager");
	if (hpmwnd == NULL) {
		wprintf(L"Failed to locate the desktop window (%d)\n", GetLastError());

		free(pselfsid);

		return 1;
	}

	GetWindowThreadProcessId(hpmwnd, &dwpmproc);
	CloseHandle(hpmwnd);

	if (!dwpmproc) {
		wprintf(L"Failed to get EXPLORER.EXE process ID (%d)\n", GetLastError());

		free(pselfsid);

		return 1;
	}

	wprintf(L"EXPLORER.EXE process ID is %d\n", dwpmproc);


	/* steal the console user's access token for impersonation */

	if (!EnablePriv(SE_DEBUG_NAME)) {
		wprintf(L"Failed to enable %s (%d)\n", SE_DEBUG_NAME, GetLastError());

		free(pselfsid);

		return 1;
	}
	
	hpmproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwpmproc);
	if (hpmproc == NULL) {
		wprintf(L"Failed to open EXPLORER.EXE process for all access (%d)\n", GetLastError());

		free(pselfsid);

		return 1;
	}

	if (!EnablePriv(SE_TAKE_OWNERSHIP_NAME)) {
		wprintf(L"Failed to enable %s (%d)\n", SE_TAKE_OWNERSHIP_NAME, GetLastError());

		free(pselfsid);
		CloseHandle(hpmproc);

		return 1;
	}
	
	if (!OpenProcessToken(hpmproc, WRITE_OWNER, &hpmtok)) {
		wprintf(L"Failed to open EXPLORER.EXE access token for WRITE_OWNER (%d)\n", GetLastError());

		free(pselfsid);
		CloseHandle(hpmproc);

		return 1;
	}

	psd = (SECURITY_DESCRIPTOR*)malloc(sizeof(SECURITY_DESCRIPTOR));
	InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorOwner(psd, pselfsid, 0);

	if (!SetKernelObjectSecurity(hpmtok, OWNER_SECURITY_INFORMATION, psd)) {
		wprintf(L"Failed to take ownership of EXPLORER.EXE access token (%d)\n", GetLastError());

		free(psd);
		free(pselfsid);
		CloseHandle(hpmproc);

		return 1;
	}

	free(psd);
	CloseHandle(hpmtok);

	if (!OpenProcessToken(hpmproc, READ_CONTROL | WRITE_DAC, &hpmtok)) {
		wprintf(L"Failed to re-open EXPLORER.EXE access token for WRITE_DAC (%d)\n", GetLastError());

		free(pselfsid);
		CloseHandle(hpmproc);

		return 1;
	}

	if (!GrantDaclPermissions(hpmtok, pselfsid, TOKEN_ALL_ACCESS)) {
		wprintf(L"Failed to adjust EXPLORER.EXE access token DACL (%d)\n", GetLastError());

		free(pselfsid);
		CloseHandle(hpmproc);
		
		return 1;
	}

	CloseHandle(hpmtok);

	if (!OpenProcessToken(hpmproc, TOKEN_DUPLICATE, &hpmtok)) {
		wprintf(L"Failed to re-open EXPLORER.EXE access token for TOKEN_DUPLICATE (%d)\n", GetLastError());

		free(pselfsid);
		CloseHandle(hpmproc);

		return 1;
	}

	if (!DuplicateTokenEx(hpmtok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hnewtok)) {
		wprintf(L"Failed to duplicate EXPLORER.EXE access token (%d)\n", GetLastError());

		free(pselfsid);
		CloseHandle(hpmtok);
		CloseHandle(hpmproc);

		return 1;
	}

	if (!GetOwnerLogonName(hpmproc, &logonname, &domain)) {
		wprintf(L"Failed to get EXPLORER.EXE owner name (%d)", GetLastError());

		free(pselfsid);
		CloseHandle(hpmtok);
		CloseHandle(hpmproc);

		return 1;
	}

	CloseHandle(hpmtok);
	CloseHandle(hpmproc);

	if (!ImpersonateLoggedOnUser(hnewtok)) {
		wprintf(L"Failed to impersonate the console user (%d)\n", GetLastError());

		free(pselfsid);
		CloseHandle(hnewtok);

		return 1;
	}

	wprintf(L"Now executing as %s\\%s\n", domain, logonname);
	free(logonname);
	free(domain);

	free(pselfsid);
	CloseHandle(hnewtok);


	/* set the console user's wallpaper */

	if (!SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (void*)argv[1], SPIF_SENDCHANGE)) {
		wprintf(L"Failed to set desktop wallpaper (%d)\n", GetLastError());
		return 1;
	}

	wprintf(L"Desktop wallpaper set successfully\n");
	RevertToSelf();

	return 0;
}

BOOL GetUserSid(HANDLE htok, PSID *psid)
{
	BOOL result = FALSE;
	DWORD dwlength = 0;
	TOKEN_INFORMATION_CLASS tic = TokenUser;
	PTOKEN_USER ptu = NULL;

	if (!GetTokenInformation(htok, tic, (LPVOID)ptu, 0, &dwlength)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			ptu = (PTOKEN_USER)malloc(dwlength);
			memset(ptu, 0, dwlength);
		} else {
			wprintf(L"Failed to get the token user length (%d)\n", GetLastError());
			return FALSE;
		}
	}
	
	if (!GetTokenInformation(htok, tic, (LPVOID)ptu, dwlength, &dwlength)) {
		wprintf(L"Failed to get the token user (%d)\n", GetLastError());
		free(ptu);

		return FALSE;
	}

	dwlength = GetLengthSid(ptu->User.Sid);
	*psid = (PSID)malloc(dwlength);
	memset(*psid, 0, dwlength);
	
	if (!CopySid(dwlength, *psid, ptu->User.Sid)) {
		wprintf(L"Failed to copy the user SID (%d)\n", GetLastError());

		free(psid);
		free(ptu);

		return FALSE;
	}

	return TRUE;
}

BOOL EnablePriv(LPCWSTR privname)
{
	HANDLE htok;
	TOKEN_PRIVILEGES newtp;
	TOKEN_PRIVILEGES oldtp;
	DWORD dwtpsz = sizeof(TOKEN_PRIVILEGES);
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &htok)) {
		wprintf(L"Failed to acquire process token (%d)\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, privname, &luid)) {
		wprintf(L"Failed to lookup privilege (%d)\n", GetLastError());
		CloseHandle(htok);
		return FALSE;
	}

	memset(&newtp, 0, sizeof(newtp));
	newtp.PrivilegeCount = 1;
	newtp.Privileges[0].Luid = luid;
	newtp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if (!AdjustTokenPrivileges(htok, FALSE, &newtp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwtpsz)) {
		wprintf(L"Failed to adjust token privileges (%d)\n", GetLastError());
		CloseHandle(htok);
		return FALSE;
	}

	wprintf(L"%s enabled\n", privname);
	return TRUE;
}

BOOL GrantDaclPermissions(HANDLE huserobj, PSID psid, ACCESS_MASK mask)
{
	ACCESS_ALLOWED_ACE *pace;
	ACL_SIZE_INFORMATION aclSizeInfo;
	BOOL bDaclExist;
	BOOL bDaclPresent;
	DWORD dwNewAclSize;
	DWORD dwSidSize = 0;
	DWORD dwSdSizeNeeded;
	PACL pacl;
	PACL pNewAcl;
	PSECURITY_DESCRIPTOR psd = NULL;
	PSECURITY_DESCRIPTOR psdNew = NULL;
	PVOID pTempAce;
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	unsigned int i;
	BOOL ret = FALSE;

	if (!GetUserObjectSecurity(huserobj, &si, psd, dwSidSize, &dwSdSizeNeeded)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			psd = (SECURITY_DESCRIPTOR*)malloc(dwSdSizeNeeded);
			memset(psd, 0, dwSdSizeNeeded);
			
			psdNew = (SECURITY_DESCRIPTOR*)malloc(dwSdSizeNeeded);
			memset(psdNew, 0, dwSdSizeNeeded);

			dwSidSize = dwSdSizeNeeded;

			if (!GetUserObjectSecurity(huserobj, &si, psd, dwSidSize, &dwSdSizeNeeded)) {
				wprintf(L"Failed to obtain object security info (%d)\n", GetLastError());

				free(psd);
				free(psdNew);

				return ret;
			}
		} else
			return ret;
	}

	InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION);
	if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist)) {
		wprintf(L"Failed to obtain object DACL (%d)\n", GetLastError());

		free(psd);
		free(psdNew);

		return ret;
	}

	memset(&aclSizeInfo, 0, sizeof(ACL_SIZE_INFORMATION));
	aclSizeInfo.AclBytesInUse = sizeof(ACL);
	
	if (pacl != NULL) {
		if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
			wprintf(L"Failed to read ACL info (%d)\n", GetLastError());

			free(psd);
			free(psdNew);

			return ret;
		}
	}

	dwNewAclSize = aclSizeInfo.AclBytesInUse 
		+ (2 * sizeof(ACCESS_ALLOWED_ACE)) 
		+ (2 * GetLengthSid(psid)) 
		- (2 * sizeof(DWORD));

	pNewAcl = (ACL*)malloc(dwNewAclSize);
	InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION);

	/* copy any existing ace's to the new dacl */
	if (bDaclPresent && aclSizeInfo.AceCount) {
		for (i = 0; i < aclSizeInfo.AceCount; i++) {
			GetAce(pacl, i, &pTempAce);
			AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize);
		}
	}

	pace = (ACCESS_ALLOWED_ACE*)malloc(sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
	pace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
	pace->Header.AceFlags = CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
	pace->Header.AceSize = (WORD)(sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
	pace->Mask = GENERIC_ALL;

	CopySid(GetLengthSid(psid), &pace->SidStart, psid);
	AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize);

	pace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
	pace->Mask = mask;
	AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize);
	
	SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE);

	ret = SetUserObjectSecurity(huserobj, &si, psdNew);
	if (!ret)
		wprintf(L"Failed to set object security info (%d)\n", GetLastError());
	
	free(psd);
	free(psdNew);
	free(pNewAcl);
	free(pace);

	return ret;
}

BOOL GetOwnerLogonName(HANDLE huserobj, wchar_t **logonname, wchar_t **domain)
{
	SECURITY_DESCRIPTOR *psd;
	DWORD dwsdsz;
	PSID powner;
	BOOL isdefaulted = NULL;
	DWORD namesz = 0;
	DWORD domsz = 0;
	SID_NAME_USE snu;

	if (!GetKernelObjectSecurity(huserobj, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, NULL, 0, &dwsdsz) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		wprintf(L"Failed to get buffer size for object security info (%d)\n", GetLastError());
		return FALSE;
	}

	psd = (SECURITY_DESCRIPTOR*)malloc(dwsdsz);
	if (!GetKernelObjectSecurity(huserobj, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, psd, dwsdsz, &dwsdsz)) {
		wprintf(L"Failed to read object security info (%d)\n", GetLastError());
		return FALSE;
	}

	if (!GetSecurityDescriptorOwner(psd, &powner, &isdefaulted)) {
		wprintf(L"Failed to read security descriptor owner (%d)\n", GetLastError());
		return FALSE;
	}
	
	if (!IsValidSid(powner)) {
		wprintf(L"Owner SID is not valid\n");
		return FALSE;
	}

	if (!LookupAccountSid(NULL, powner, NULL, &namesz, NULL, &domsz, &snu) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		wprintf(L"Failed to get buffer size for account lookup (%d)\n", GetLastError());
		return FALSE;
	}
	
	*logonname = (wchar_t*)malloc(sizeof(wchar_t) * namesz);
	*domain = (wchar_t*)malloc(sizeof(wchar_t) * domsz);
	memset(*logonname, 0, namesz);
	memset(*domain, 0, domsz);

	if (!LookupAccountSid(NULL, powner, *logonname, &namesz, *domain, &domsz, &snu)) {
		wprintf(L"Failed to lookup account by SID (%d)\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

