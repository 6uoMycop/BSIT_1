#include <iostream>
#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <ntsecapi.h> 

using namespace std;

HMODULE netapi;

typedef NET_API_STATUS (NET_API_FUNCTION *_NetLocalGroupGetMembers)(LPCWSTR servername, LPCWSTR localgroupname, DWORD   level,    LPBYTE *bufptr,     DWORD   prefmaxlen,   LPDWORD entriesread,  LPDWORD    totalentries,  PDWORD_PTR resumehandle);
typedef NET_API_STATUS (NET_API_FUNCTION *_NetUserGetLocalGroups  )(LPCWSTR servername, LPCWSTR username,       DWORD   level,    DWORD   flags,      LPBYTE *bufptr,       DWORD prefmaxlen,     LPDWORD    entriesread,   LPDWORD totalentries   );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetUserEnum            )(LPCWSTR servername, DWORD   level,          DWORD   filter,   LPBYTE *bufptr,     DWORD   prefmaxlen,   LPDWORD entriesread,  LPDWORD    totalentries,  PDWORD resume_handle   );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetLocalGroupEnum      )(LPCWSTR servername, DWORD   level,          LPBYTE *bufptr,   DWORD   prefmaxlen, LPDWORD entriesread,  LPDWORD totalentries, PDWORD_PTR resumehandle                          );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetUserGetGroups       )(LPCWSTR servername, LPCWSTR username,       DWORD   level,    LPBYTE *bufptr,     DWORD   prefmaxlen,   LPDWORD entriesread,  LPDWORD    totalentries                          );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetGroupEnum           )(LPCWSTR servername, DWORD   level,          LPBYTE *bufptr,   DWORD   prefmaxlen, LPDWORD entriesread,  LPDWORD totalentries, PDWORD_PTR resume_handle                         );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetLocalGroupAddMembers)(LPCWSTR servername, LPCWSTR groupname,      DWORD   level,    LPBYTE  buf,        DWORD   totalentries                                                                         );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetLocalGroupDelMembers)(LPCWSTR servername, LPCWSTR groupname,      DWORD   level,    LPBYTE  buf,        DWORD   totalentries                                                                         );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetLocalGroupSetInfo   )(LPCWSTR servername, LPCWSTR groupname,      DWORD   level,    LPBYTE  buf,        LPDWORD parm_err                                                                             );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetGroupSetInfo        )(LPCWSTR servername, LPCWSTR groupname,      DWORD   level,    LPBYTE  buf,        LPDWORD parm_err                                                                             );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetUserSetInfo         )(LPCWSTR servername, LPCWSTR username,       DWORD   level,	  LPBYTE  buf,        LPDWORD parm_err                                                                             );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetLocalGroupAdd       )(LPCWSTR servername, DWORD   level,          LPBYTE  buf,      LPDWORD parm_err                                                                                                 );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetUserGetInfo         )(LPCWSTR servername, LPCWSTR username,       DWORD   level,    LPBYTE *bufptr                                                                                                   );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetGroupAdd            )(LPCWSTR servername, DWORD   level,          LPBYTE  buf,      LPDWORD parm_err                                                                                                 );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetUserAdd             )(LPCWSTR servername, DWORD   level,          LPBYTE  buf,      LPDWORD parm_err                                                                                                 );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetGroupAddUser        )(LPCWSTR servername, LPCWSTR GroupName,      LPCWSTR username                                                                                                                   );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetGroupDelUser        )(LPCWSTR servername, LPCWSTR GroupName,      LPCWSTR Username                                                                                                                   );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetLocalGroupDel       )(LPCWSTR servername, LPCWSTR groupname                                                                                                                                          );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetGroupDel            )(LPCWSTR servername, LPCWSTR groupname                                                                                                                                          );
typedef NET_API_STATUS (NET_API_FUNCTION *_NetUserDel             )(LPCWSTR servername, LPCWSTR username                                                                                                                                           );

_NetLocalGroupAddMembers __NetLocalGroupAddMembers;
_NetLocalGroupDelMembers __NetLocalGroupDelMembers;
_NetLocalGroupGetMembers __NetLocalGroupGetMembers;
_NetUserGetLocalGroups	 __NetUserGetLocalGroups;
_NetLocalGroupSetInfo	 __NetLocalGroupSetInfo;
_NetLocalGroupEnum		 __NetLocalGroupEnum;
_NetUserGetGroups		 __NetUserGetGroups;
_NetLocalGroupDel		 __NetLocalGroupDel;
_NetGroupSetInfo		 __NetGroupSetInfo;
_NetLocalGroupAdd		 __NetLocalGroupAdd;
_NetGroupAddUser		 __NetGroupAddUser;
_NetGroupDelUser		 __NetGroupDelUser;
_NetUserSetInfo			 __NetUserSetInfo;
_NetUserGetInfo			 __NetUserGetInfo;
_NetGroupEnum			 __NetGroupEnum;
_NetUserEnum             __NetUserEnum;
_NetGroupAdd			 __NetGroupAdd;
_NetGroupDel			 __NetGroupDel;
_NetUserAdd				 __NetUserAdd;
_NetUserDel				 __NetUserDel;

BOOL InitDynamicLibrary()
{
	netapi = LoadLibrary(L"netapi32.dll");
	if (netapi == NULL)
	{
		return FALSE;
	}

	__NetLocalGroupAddMembers = (_NetLocalGroupAddMembers)GetProcAddress(netapi, "NetLocalGroupAddMembers");
	__NetLocalGroupDelMembers = (_NetLocalGroupDelMembers)GetProcAddress(netapi, "NetLocalGroupDelMembers");
	__NetLocalGroupGetMembers = (_NetLocalGroupGetMembers)GetProcAddress(netapi, "NetLocalGroupGetMembers");
	__NetUserGetLocalGroups   = (_NetUserGetLocalGroups  )GetProcAddress(netapi, "NetUserGetLocalGroups"  );
	__NetLocalGroupSetInfo    = (_NetLocalGroupSetInfo   )GetProcAddress(netapi, "NetLocalGroupSetInfo"   );
	__NetLocalGroupEnum       = (_NetLocalGroupEnum      )GetProcAddress(netapi, "NetLocalGroupEnum"      );
	__NetUserGetGroups        = (_NetUserGetGroups       )GetProcAddress(netapi, "NetUserGetGroups"       );
	__NetLocalGroupAdd        = (_NetLocalGroupAdd       )GetProcAddress(netapi, "NetLocalGroupAdd"       );
	__NetLocalGroupDel        = (_NetLocalGroupDel       )GetProcAddress(netapi, "NetLocalGroupDel"       );
	__NetGroupSetInfo         = (_NetGroupSetInfo        )GetProcAddress(netapi, "NetGroupSetInfo"        );
	__NetGroupAddUser         = (_NetGroupAddUser        )GetProcAddress(netapi, "NetGroupAddUser"        );
	__NetGroupDelUser         = (_NetGroupDelUser        )GetProcAddress(netapi, "NetGroupDelUser"        );
	__NetUserGetInfo          = (_NetUserGetInfo         )GetProcAddress(netapi, "NetUserGetInfo"         );
	__NetUserSetInfo          = (_NetUserSetInfo         )GetProcAddress(netapi, "NetUserSetInfo"         );
	__NetGroupEnum            = (_NetGroupEnum           )GetProcAddress(netapi, "NetGroupEnum"           );
	__NetUserEnum             = (_NetUserEnum            )GetProcAddress(netapi, "NetUserEnum"            );
	__NetGroupAdd             = (_NetGroupAdd            )GetProcAddress(netapi, "NetGroupAdd"            );
	__NetGroupDel             = (_NetGroupDel            )GetProcAddress(netapi, "NetGroupDel"            );
	__NetUserAdd              = (_NetUserAdd             )GetProcAddress(netapi, "NetUserAdd"             );
	__NetUserDel              = (_NetUserDel             )GetProcAddress(netapi, "NetUserDel"             );

	return TRUE;
}

void ErrorOutput()
{
	DWORD Status = GetLastError();
	cout << "Error (" << Status << "): ";
	switch (Status)
	{
	case ERROR_ACCESS_DENIED:
	{
		cout << "ERROR_ACCESS_DENIED\n";
		break;
	}
	case NERR_InvalidComputer:
	{
		cout << "NERR_InvalidComputer\n";
		break;
	}
	case NERR_NotPrimary:
	{
		cout << "NERR_NotPrimary\n";
		break;
	}
	case NERR_UserNotFound:
	{
		cout << "NERR_UserNotFound\n";
		break;
	}
	case NERR_GroupExists:
	{
		cout << "NERR_GroupExists\n";
		break;
	}
	case NERR_GroupNotFound:
	{
		cout << "NERR_GroupNotFound\n";
		break;
	}
	case NERR_UserExists:
	{
		cout << "NERR_UserExists\n";
		break;
	}
	case NERR_PasswordTooShort:
	{
		cout << "NERR_PasswordTooShort\n";
		break;
	}
	case ERROR_BAD_USERNAME:
	{
		cout << "ERROR_BAD_USERNAME\n";
		break;
	}
	case ERROR_INVALID_ACCOUNT_NAME:
	{
		cout << "ERROR_INVALID_ACCOUNT_NAME\n";
		break;
	}
	case ERROR_INVALID_PARAMETER:
	{
		cout << "ERROR_INVALID_PARAMETER\n";
		break;
	}
	case NERR_SpeGroupOp:
	{
		cout << "NERR_SpeGroupOp\n";
		break;
	}
	case NERR_LastAdmin:
	{
		cout << "NERR_LastAdmin\n";
		break;
	}
	case NERR_BadPassword:
	{
		cout << "NERR_BadPassword\n";
		break;
	}
	case ERROR_ALIAS_EXISTS:
	{
		cout << "ERROR_ALIAS_EXISTS\n";
		break;
	}
	case ERROR_INVALID_LEVEL:
	{
		cout << "ERROR_INVALID_LEVEL\n";
		break;
	}
	
	default:
	{
		cout << "Undefined error. Check MSDN\n";
		break;
	}
	}
}

void UsersInfo()
{
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_0 pTmpBuf;
	LPGROUP_USERS_INFO_1 pBuf1;
	LPLOCALGROUP_USERS_INFO_0 pBuf2;
	LPUSER_INFO_4 pTmpBuf1;
	NET_API_STATUS nStatus;
	DWORD dwEntriesRead = 0;
	DWORD dwEntriesRead1 = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);

	nStatus = __NetUserEnum(
		(LPCWSTR)pszServerName,
		0,
		FILTER_NORMAL_ACCOUNT,
		(LPBYTE*)&pBuf,
		MAX_PREFERRED_LENGTH,
		&dwEntriesRead,
		&dwTotalEntries,
		&dwResumeHandle);

	if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
	{
		pTmpBuf = pBuf;
		for (unsigned int i = 0; i < dwEntriesRead; i++)
		{
			if (pTmpBuf == NULL)
			{
				fprintf(stderr, "An access violation has occurred\n");
				break;
			}
			__NetUserGetInfo((LPCWSTR)pszServerName, pTmpBuf->usri0_name, 4, (LPBYTE*)&pTmpBuf1);
			TCHAR priv[16];
			if (pTmpBuf1->usri4_priv == USER_PRIV_GUEST)
			{
				lstrcpyW(priv, L"Guest");
			}
			else if (pTmpBuf1->usri4_priv == USER_PRIV_USER)
			{
				lstrcpyW(priv, L"User");
			}
			else if (pTmpBuf1->usri4_priv == USER_PRIV_ADMIN)
			{
				lstrcpyW(priv, L"Admin");
			}

			LPWSTR pSID = NULL;
			ConvertSidToStringSid(pTmpBuf1->usri4_user_sid, &pSID);

			wcout << "Username:\t" << pTmpBuf1->usri4_name                                                         << endl <<
					 "Comment:\t"  << (((pTmpBuf1->usri4_comment)[0] == '\0') ? L"None" : pTmpBuf1->usri4_comment) << endl <<
					 "SID:\t\t"    << pSID                                                                         << endl <<
					 "Type:\t\t"   << priv                                                                         << endl;

			__NetUserGetGroups((LPCWSTR)pszServerName, pTmpBuf->usri0_name, 1, (LPBYTE*)&pBuf1, MAX_PREFERRED_LENGTH, &dwEntriesRead1, &dwTotalEntries);
			wcout << "Global group:\t" << pBuf1->grui1_name << endl << 
					 "Attributes:\t";
			switch (pBuf1->grui1_attributes)
			{
			case SE_GROUP_MANDATORY:
			{
				cout << "The group is mandatory.";
				break;
			}
			case SE_GROUP_ENABLED_BY_DEFAULT:
			{
				cout << "The group is enabled for access checks by default.";
				break;
			}
			case SE_GROUP_ENABLED:
			{
				cout << "The group is enabled for access checks.";
				break;
			}
			case SE_GROUP_OWNER:
			{
				cout << "The group identifies a group account for which the user of the token is the owner of the group.";
				break;
			}
			case SE_GROUP_USE_FOR_DENY_ONLY:
			{
				cout << "The group is used for deny only purposes. When this attribute is set, the SE_GROUP_ENABLED attribute must not be set.";
				break;
			}
			case SE_GROUP_INTEGRITY:
			{
				cout << "The group is used for integrity. This attribute is available on Windows Vista and later.";
				break;
			}
			case SE_GROUP_INTEGRITY_ENABLED:
			{
				cout << "The group is enabled for integrity level. This attribute is available on Windows Vista and later.";
				break;
			}
			case SE_GROUP_LOGON_ID:
			{
				cout << "The group is used to identify a logon session associated with an access token.";
				break;
			}
			case SE_GROUP_RESOURCE:
			{
				cout << "The group identifies a domain-local group.";
			}
			default:
			{
				cout << "None";
				break;
			}
			}
			cout << endl;

			DWORD dwFlags = LG_INCLUDE_INDIRECT;

			nStatus = __NetUserGetLocalGroups((LPCWSTR)pszServerName, pTmpBuf->usri0_name, 0, dwFlags, (LPBYTE *)&pBuf2, MAX_PREFERRED_LENGTH, &dwEntriesRead1, &dwTotalEntries);

			if (nStatus == NERR_Success)
			{
				LPLOCALGROUP_USERS_INFO_0 pTmpBuf;

				cout << "Local groups:\t";
				if ((pTmpBuf = pBuf2) != NULL)
				{
					wcout << pTmpBuf->lgrui0_name << endl;
					pTmpBuf++;
					for (unsigned int i = 1; i < dwEntriesRead1; i++)
					{
						wcout << "\t\t" << pTmpBuf->lgrui0_name << endl;
						pTmpBuf++;
					}
				}
				else
				{
					cout << "None\n";
				}
			}

			NTSTATUS ntsResult;
			LSA_OBJECT_ATTRIBUTES ObjAttributes;
			LSA_HANDLE lsahPolicyHandle;
			ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
			PSID sid1 = pTmpBuf1->usri4_user_sid;
			ntsResult = LsaOpenPolicy(NULL, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
			PLSA_UNICODE_STRING rights;
			ULONG count = 0;
			ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, sid1, &rights, &count);
			cout << "Privileges:\t";
			if (ntsResult == 0)
			{
				if (count)
				{
					wcout << rights->Buffer << endl;
					rights++;
					for (unsigned int k = 1; k < count; k++)
					{
						wcout << "\t\t" << rights->Buffer << endl;
						rights++;
					}
				}
				else
				{
					cout << "None\n";
				}
			}
			else
			{
				if (ntsResult == STATUS_INVALID_HANDLE)
				{
					cout << "LsaEnumerateAccountRights() returned STATUS_INVALID_HANDLE\n";
				}
				else
				{
					cout << "LsaEnumerateAccountRights() returned 0x" << hex << ntsResult << "\n";
				}
			}

			cout << endl << endl;
			pTmpBuf++;
		}
	}
}

BOOL AddMachineAccount(LPWSTR wAccount, LPWSTR wPassword)
{
	USER_INFO_1 ui;
	DWORD cbLength;
	DWORD dwError;
	WCHAR wTargetComputer[MAX_COMPUTERNAME_LENGTH];
	DWORD len = MAX_COMPUTERNAME_LENGTH;

	// Obtain number of chars in computer account name.
	cbLength = lstrlenW(wAccount);

	// Ensure computer name doesn't exceed maximum length.
	if (cbLength > MAX_COMPUTERNAME_LENGTH)
	{
		SetLastError(ERROR_INVALID_ACCOUNT_NAME);
		return FALSE;
	}

	if (wAccount == NULL)
	{
		return FALSE;
	}

	///wAccount[cbLength] = L'$'; // Computer account names have a trailing Unicode '$'.
	///wAccount[cbLength + 1] = L'\0'; // terminate the string

	// If the password is greater than the max allowed, truncate.
	if (cbLength > LM20_PWLEN)
	{
		wPassword[LM20_PWLEN] = L'\0';
	}

	// Initialize the USER_INFO_1 structure.
	ZeroMemory(&ui, sizeof(ui));

	ui.usri1_name     = wAccount;
	ui.usri1_password = wPassword;
	ui.usri1_priv     = USER_PRIV_USER;
	ui.usri1_flags    = UF_SCRIPT;

	GetComputerName(wTargetComputer, &len);

	dwError = __NetUserAdd(
		wTargetComputer,    // target computer name
		1,                  // info level
		(LPBYTE)&ui,		// buffer
		NULL
	);

	// Indicate whether the function was successful.
	if (dwError == NO_ERROR)
	{
		return TRUE;
	}
	else
	{
		SetLastError(dwError);
		return FALSE;
	}
}

BOOL DeleteAccount(LPWSTR wAccount)
{
	DWORD i = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &i);
	NET_API_STATUS nStatus;

	nStatus = __NetUserDel(pszServerName, wAccount);
	
	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL ChangeAccount(LPWSTR wName, LPWSTR wNewName, LPWSTR wPassword)
{
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);

	LPUSER_INFO_0 uiName = new USER_INFO_0;
	LPUSER_INFO_1003 uiPass = new USER_INFO_1003;
	uiName->usri0_name = wNewName;
	uiPass->usri1003_password = wPassword;

	NET_API_STATUS nStatus;

	nStatus = __NetUserSetInfo(pszServerName, wName, 0, (LPBYTE)uiName, 0);
	if (nStatus != NERR_Success)
	{
		SetLastError(nStatus);
		return FALSE;
	}

	nStatus = __NetUserSetInfo(pszServerName, wNewName, 1003, (LPBYTE)uiPass, 0);
	if (nStatus != NERR_Success)
	{
		SetLastError(nStatus);
		return FALSE;
	}

	return TRUE;
}

BOOL InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
	{
		return FALSE;
	}
	if (NULL != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
		{
			return FALSE;
		}
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}

TCHAR *GetGroupSid(TCHAR *wName)
{
	LSA_UNICODE_STRING name;
	NTSTATUS ntsResult;
	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	LSA_HANDLE lsahPolicyHandle;
	PLSA_REFERENCED_DOMAIN_LIST domainlist;
	PLSA_TRANSLATED_SID2 Sids;
	WCHAR SystemName[64] = L""; //L"IEWIN7";
	USHORT SystemNameLength;
	LSA_UNICODE_STRING lusSystemName;

	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

	SystemNameLength = (USHORT)wcslen(SystemName);
	lusSystemName.Buffer = SystemName;
	lusSystemName.Length = SystemNameLength *sizeof(WCHAR);
	lusSystemName.MaximumLength = (SystemNameLength + 1) * sizeof(WCHAR);

	ntsResult = LsaOpenPolicy(&lusSystemName, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
	if (ntsResult != ERROR_SUCCESS)
	{
		cout << "error in LsaOpenPolicy errcode: " << LsaNtStatusToWinError(ntsResult) << endl;
	}

	if (!InitLsaString(&name, wName))
	{
		cout << "Failed InitLsaString" << endl;
	}

	ntsResult = LsaLookupNames2(lsahPolicyHandle, 0, 1, &name, &domainlist, &Sids);

	if (ntsResult != ERROR_SUCCESS)
	{
		cout << "error in LsaLookupNames errcode: " << LsaNtStatusToWinError(ntsResult) << endl;
	}
	TCHAR *sid;
	ConvertSidToStringSid(Sids->Sid, &sid);
	return sid;
}

void GroupsInfo()
{
	LPGROUP_INFO_0 pBuf;
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);
	NET_API_STATUS nStatus;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	nStatus = __NetGroupEnum((LPCWSTR)pszServerName, 0, (LPBYTE *)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
	if (nStatus == NERR_Success)
	{
		LPGROUP_INFO_0 pTmpBuf;

		if ((pTmpBuf = pBuf) != NULL)
		{
			cout << "Global group_s:" << endl;

			for (unsigned int i = 0; i < dwEntriesRead; i++)
			{

				if (pTmpBuf == NULL)
				{
					fprintf(stderr, "An access violation has occurred\n");
					break;
				}

				wcout << L"Name:\t\t" << pTmpBuf->grpi0_name << endl << endl;

				pTmpBuf++;
			}
		}
	}

	PLOCALGROUP_INFO_0 pBuf11 = NULL;
	PLOCALGROUP_INFO_0 pTmpBuf11 = NULL;
	PGROUP_INFO_3 bufff = NULL;
	DWORD totalentries = 0;
	DWORD rednum = 0;
	DWORD_PTR handler = 0;
	__NetLocalGroupEnum(0, 0, (LPBYTE *)&pBuf11, MAX_PREFERRED_LENGTH, &rednum, &totalentries, &handler);
	cout << "Local group_s:" << endl;
	if ((pTmpBuf11 = pBuf11) != NULL)
	{
		for (unsigned int i = 0; i < rednum; i++)
		{
			TCHAR *sidstring = GetGroupSid(pTmpBuf11->lgrpi0_name);
			wcout << L"Name:\t" << pTmpBuf11->lgrpi0_name << endl << 
					  "SID:\t"  << sidstring              << endl <<
					  "Users:"                            << endl;
			PLOCALGROUP_MEMBERS_INFO_1 buf1 = NULL, buf2 = NULL;
			DWORD rednum1 = 0, totalentries1 = 0, handler1 = 0;
			__NetLocalGroupGetMembers(0, pTmpBuf11->lgrpi0_name, 1, (LPBYTE *)&buf1, MAX_PREFERRED_LENGTH, &rednum1, &totalentries1, &handler1);
			buf2 = buf1;
			for (unsigned int j = 0; j < rednum1; j++)
			{
				wcout << L"\tUser:\t" << buf2->lgrmi1_name << endl;
				LPTSTR sStringSid = NULL;
				ConvertSidToStringSid(buf2->lgrmi1_sid, &sStringSid);
				wcout << L"\tSID:\t" << sStringSid << endl << endl;
				buf2++;
			}
			PSID sid;
			ConvertStringSidToSid(sidstring, &sid);
			pTmpBuf11++;
			cout << endl << endl;
		}
	}
	pBuf11 = NULL;

	cout << "Privileges:" << endl;
	__NetLocalGroupEnum(0, 0, (LPBYTE *)&pBuf11, MAX_PREFERRED_LENGTH, &rednum, &totalentries, &handler);
	if ((pTmpBuf11 = pBuf11) != NULL)
	{
		for (unsigned int i = 0; i < rednum; i++)
		{
			TCHAR *sidstring = GetGroupSid(pTmpBuf11->lgrpi0_name);
			PSID sid;
			ConvertStringSidToSid(sidstring, &sid);
			wcout << pTmpBuf11->lgrpi0_name << L" (" << sidstring << L")" << endl;
			NTSTATUS ntsResult;
			LSA_OBJECT_ATTRIBUTES ObjAttributes;
			LSA_HANDLE lsahPolicyHandle;
			ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
			ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
			if (ntsResult != ERROR_SUCCESS)
			{
				cout << "error in LsaOpenPolicy errcode: " << LsaNtStatusToWinError(ntsResult) << endl;
			}
			PLSA_UNICODE_STRING rights;
			ULONG count;
			ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, sid, (PLSA_UNICODE_STRING *)&rights, &count);
			for (unsigned int k = 0; k < count; k++)
			{
				wcout << L"\t" << rights->Buffer;
				rights++;
			}
			cout << endl << endl;
			pTmpBuf11++;
		}
	}
	
}

BOOL AddGlobalGroup(LPWSTR wName)
{
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);
	LPGROUP_INFO_0 pBuf = new GROUP_INFO_0;
	pBuf->grpi0_name = wName;
	NET_API_STATUS nStatus;

	nStatus = __NetGroupAdd(pszServerName, 0, (LPBYTE)pBuf, 0);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL AddLocalGroup(LPWSTR wName)
{
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);
	LPLOCALGROUP_INFO_0 pBuf = new LOCALGROUP_INFO_0;
	pBuf->lgrpi0_name = wName;
	NET_API_STATUS nStatus;

	nStatus = __NetLocalGroupAdd(pszServerName, 0, (LPBYTE)pBuf, 0);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL DeleteGlobalGroup(LPWSTR wName)
{
	DWORD i = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &i);
	NET_API_STATUS nStatus;

	nStatus = __NetGroupDel(pszServerName, wName);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL DeleteLocalGroup(LPWSTR wName)
{
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);
	NET_API_STATUS nStatus;

	nStatus = __NetLocalGroupDel(pszServerName, wName);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL ChangeGlobalGroup(LPWSTR wName, LPWSTR wNewName, LPWSTR wNewComment)
{
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);
	LPGROUP_INFO_0 pBuf = new GROUP_INFO_0;
	LPGROUP_INFO_1 pBuf1 = new GROUP_INFO_1;
	pBuf->grpi0_name = wNewName;
	pBuf1->grpi1_name = wName;
	pBuf1->grpi1_comment = wNewComment;
	NET_API_STATUS nStatus;

	nStatus = __NetGroupSetInfo(pszServerName, wName, 1, (LPBYTE)pBuf1, 0);
	if (nStatus != NERR_Success)
	{
		SetLastError(nStatus);
		return FALSE;
	}

	nStatus = __NetGroupSetInfo(pszServerName, wName, 0, (LPBYTE)pBuf, 0);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL ChangeLocalGroup(LPWSTR wName, LPWSTR wNewName, LPWSTR wNewComment)
{
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);
	LPLOCALGROUP_INFO_0 pBuf = new LOCALGROUP_INFO_0;
	LPLOCALGROUP_INFO_1 pBuf1 = new LOCALGROUP_INFO_1;
	pBuf->lgrpi0_name = wNewName;
	pBuf1->lgrpi1_name = wName;
	pBuf1->lgrpi1_comment = wNewComment;
	NET_API_STATUS nStatus;

	nStatus = __NetLocalGroupSetInfo(pszServerName, wName, 1, (LPBYTE)pBuf1, NULL);
	if (nStatus != NERR_Success)
	{
		SetLastError(nStatus);
		return FALSE;
	}

	nStatus = __NetLocalGroupSetInfo(pszServerName, wName, 0, (LPBYTE)pBuf, NULL);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL AddAccountToGlobalGroup(LPWSTR wUsername, LPWSTR wGroup)
{
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);
	NET_API_STATUS nStatus;

	nStatus = __NetGroupAddUser(pszServerName, wGroup, wUsername);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL AddAccountToLocalGroup(LPWSTR wUsername, LPWSTR wGroup)
{
	DWORD len = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &len);
	LPLOCALGROUP_MEMBERS_INFO_3 pBuf = new LOCALGROUP_MEMBERS_INFO_3;
	pBuf->lgrmi3_domainandname = wUsername;
	NET_API_STATUS nStatus;

	nStatus = __NetLocalGroupAddMembers(pszServerName, wGroup, 3, (LPBYTE)pBuf, 1);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL DeleteAccountFromGlobalGroup(LPWSTR wUsername, LPWSTR wGroup)
{
	DWORD i = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &i);
	NET_API_STATUS nStatus;

	nStatus = __NetGroupDelUser(pszServerName, wGroup, wUsername);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

BOOL DeleteAccountFromLocalGroup(LPWSTR wUsername, LPWSTR wGroup)
{
	DWORD i = MAX_COMPUTERNAME_LENGTH;
	TCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerName(pszServerName, &i);
	LPLOCALGROUP_MEMBERS_INFO_3 pBuf = new LOCALGROUP_MEMBERS_INFO_3;
	pBuf->lgrmi3_domainandname = wUsername;
	NET_API_STATUS nStatus;
	nStatus = __NetLocalGroupDelMembers(pszServerName, wGroup, 3, (LPBYTE)pBuf, 1);

	// Indicate whether the function was successful.
	if (nStatus == NERR_Success)
	{
		return TRUE;
	}
	else
	{
		SetLastError(nStatus);
		return FALSE;
	}
}

PSID GetSid(LPWSTR wUsername)
{
	int i = 0;
	SID_NAME_USE type_of_SID;
	DWORD dwLengthOfDomainName = 0;
	DWORD dwLengthOfSID = 0;
	DWORD dwErrCode;
	SID *lpSID = NULL;
	LPTSTR lpDomainName = NULL;

	if (!LookupAccountName(
		NULL,
		wUsername,
		NULL,
		&dwLengthOfSID,
		NULL,
		&dwLengthOfDomainName,
		&type_of_SID))
	{
		dwErrCode = GetLastError();
		if (dwErrCode == ERROR_INSUFFICIENT_BUFFER)
		{
			lpSID = (SID *) new char[dwLengthOfSID];
			lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
		}
		else
		{
			printf("Lookup account name failed.\n");
			printf("Error code: %d\n", dwErrCode);
		}
	}

	if (!LookupAccountName(
		NULL,
		wUsername,
		lpSID,
		&dwLengthOfSID,
		lpDomainName,
		&dwLengthOfDomainName,
		&type_of_SID))
	{
		dwErrCode = GetLastError();
		printf("Lookup account name failed.\n");
		printf("Error code: %d\n", dwErrCode);
	}

	delete[] lpDomainName;

	return lpSID;
}

BOOL AddPrivilege(LPWSTR wName, LPWSTR wPrivilege)
{
	NTSTATUS ntsResult;
	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	LSA_HANDLE lsahPolicyHandle;
	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
	ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
	if ((ntsResult != 0))
	{
		SetLastError(LsaNtStatusToWinError(ntsResult));
		return FALSE;
	}
	LSA_UNICODE_STRING UserRights;
	ULONG CountOfRights = 1;
	InitLsaString(&UserRights, wPrivilege);
	PSID sid = GetSid(wName);

	ntsResult = LsaAddAccountRights(lsahPolicyHandle, sid, &UserRights, 1);

	delete[] sid;

	// Indicate whether the function was successful.
	if ((ntsResult == 0))
	{
		return TRUE;
	}
	else
	{
		SetLastError(ntsResult);
		return FALSE;
	}
}

BOOL RemovePrivilege(LPWSTR wName, LPWSTR wPrivilege)
{
	NTSTATUS ntsResult;
	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	LSA_HANDLE lsahPolicyHandle;
	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
	ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
	if ((ntsResult != 0))
	{
		SetLastError(LsaNtStatusToWinError(ntsResult));
		return FALSE;
	}
	LSA_UNICODE_STRING UserRights;
	ULONG CountOfRights = 1;
	InitLsaString(&UserRights, wPrivilege);
	PSID sid = GetSid(wName);

	ntsResult = LsaRemoveAccountRights(lsahPolicyHandle, sid, 0, &UserRights, 1);

	// Indicate whether the function was successful.
	if ((ntsResult == 0))
	{
		return TRUE;
	}
	else
	{
		SetLastError(ntsResult);
		return FALSE;
	}
}

int main()
{
	setlocale(LC_CTYPE, "rus");

	WCHAR sAdmins[32] = L"Администраторы";
	WCHAR sUsers[32]  = L"Пользователи";
	WCHAR sGuests[32] = L"Гости";

	if (!InitDynamicLibrary())
	{
		cout << "Error in library\n";
		system("pause");
		return 0;
	}

	int mode = 0;

	while (1)
	{
		cout << 
			"0 - exit\t\t 6 - add group"                     << endl <<
			"1 - users info\t\t 7 - delete group"            << endl <<
			"2 - add user\t\t 8 - change group"              << endl <<
			"3 - delete user\t\t 9 - add user to group"      << endl <<
			"4 - change user\t\t10 - remove user from group" << endl <<
			"5 - groups info\t\t11 - change privileges"      << endl <<
			"> ";
		cin >> mode;

		switch (mode)
		{
		case 0:
		{
			return 0;
		}
		case 1: // информация о пользователях
		{
			UsersInfo();
			break;
		}
		case 2: // создать пользователя
		{
			WCHAR username[32];
			cout << "Enter username:\n> ";
			wcin >> username;
			WCHAR password[32];
			cout << "Enter password:\n> ";
			wcin >> password;

			if (AddMachineAccount(username, password) == TRUE)
			{
				cout << "Account with username ";
				wcout << username;
				cout << ", password ";
				wcout << password;
				cout << " was created successfully\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		case 3: // удалить пользователя
		{
			WCHAR username[32];
			cout << "Enter username:\n> ";
			wcin >> username;

			if (DeleteAccount(username) == TRUE)
			{
				cout << "Account with username ";
				wcout << username;
				cout << " was deleted successfully\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		case 4: // изменить пользователя
		{
			WCHAR username[32];
			cout << "Enter username:\n> ";
			wcin >> username;
			WCHAR newusername[32];
			cout << "Enter new username:\n> ";
			wcin >> newusername;
			WCHAR newpassword[32];
			cout << "Enter new password:\n> ";
			wcin >> newpassword;
			
			if (ChangeAccount(username, newusername, newpassword) == TRUE)
			{
				cout << "Account was changed successfully\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		case 5: // информация о группах
		{
			GroupsInfo();
			break;
		}
		case 6: // создать группу
		{
			cout << "1 - local group, 2 - global group\n> ";
			cin >> mode;
			WCHAR name[32];
			cout << "Enter group\'s name:\n> ";
			wcin >> name;

			BOOL Status;

			switch (mode)
			{
			case 1:
			{
				Status = AddLocalGroup(name);
				break;
			}
			case 2:
			{
				Status = AddGlobalGroup(name);
				break;
			}
			default:
			{
				continue;
				break;
			}
			}

			if (Status == TRUE)
			{
				cout << "Group with name ";
				wcout << name;
				cout << " was created successfully\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		case 7: // удалить группу
		{
			cout << "1 - local group, 2 - global group\n> ";
			cin >> mode;
			WCHAR name[32];
			cout << "Enter group\'s name:\n> ";
			wcin >> name;

			BOOL Status;

			switch (mode)
			{
			case 1:
			{
				Status = DeleteLocalGroup(name);
				break;
			}
			case 2:
			{
				Status = DeleteGlobalGroup(name);
				break;
			}
			default:
			{
				continue;
				break;
			}
			}

			if (Status == TRUE)
			{
				cout << "Group with name ";
				wcout << name;
				cout << " was deleted successfully\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		case 8: // изменить группу
		{
			cout << "1 - local group, 2 - global group\n> ";
			cin >> mode;
			WCHAR name[32];
			cout << "Enter group\'s name:\n> ";
			wcin >> name;
			WCHAR newname[32];
			cout << "Enter group\'s new name:\n> ";
			wcin >> newname;
			WCHAR newcomment[32];
			cout << "Enter group\'s new comment:\n> ";
			wcin >> newcomment;

			BOOL Status;

			switch (mode)
			{
			case 1:
			{
				Status = ChangeLocalGroup(name, newname, newcomment);
				break;
			}
			case 2:
			{
				Status = ChangeGlobalGroup(name, newname, newcomment);
				break;
			}
			default:
			{
				continue;
				break;
			}
			}

			if (Status == TRUE)
			{
				cout << "Group's new status:\nname:\t\t";
				wcout << newname;
				cout << "\ncomment:\t";
				wcout << newcomment;
				cout << "\n\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		case 9: // добавить пользователя в группу
		{
			WCHAR group[32];
			cout << "Enter group\'s name:\n> ";
			wcin >> group;
			cout << "1 - local group, 2 - global group\n> ";
			cin >> mode;
			WCHAR username[32];
			cout << "Enter user\'s name:\n> ";
			wcin >> username;

			if (wcscmp(group, L"Administrators") == 0)
			{
				wcscpy_s(group, sAdmins);
			}
			else if (wcscmp(group, L"Users") == 0)
			{
				wcscpy_s(group, sUsers);
			}
			else if (wcscmp(group, L"Guests") == 0)
			{
				wcscpy_s(group, sGuests);
			}

			BOOL Status;

			switch (mode)
			{
			case 1:
			{
				Status = AddAccountToLocalGroup(username, group);
				break;
			}
			case 2:
			{
				Status = AddAccountToGlobalGroup(username, group);
				break;
			}
			default:
			{
				continue;
				break;
			}
			}

			if (Status == TRUE)
			{
				cout << "User ";
				wcout << username;
				cout << " was successfully added to group ";
				wcout << group;
				cout << "\n\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		case 10: // удалить пользователя из группы
		{
			WCHAR group[32];
			cout << "Enter group\'s name:\n> ";
			wcin >> group;
			cout << "1 - local group, 2 - global group\n> ";
			cin >> mode;
			WCHAR username[32];
			cout << "Enter user\'s name:\n> ";
			wcin >> username;

			if (wcscmp(group, L"Administrators") == 0)
			{
				wcscpy_s(group, sAdmins);
			}
			else if (wcscmp(group, L"Users") == 0)
			{
				wcscpy_s(group, sUsers);
			}
			else if (wcscmp(group, L"Guests") == 0)
			{
				wcscpy_s(group, sGuests);
			}

			BOOL Status;

			switch (mode)
			{
			case 1:
			{
				Status = DeleteAccountFromLocalGroup(username, group);
				break;
			}
			case 2:
			{
				Status = DeleteAccountFromGlobalGroup(username, group);
				break;
			}
			default:
			{
				continue;
				break;
			}
			}

			if (Status == TRUE)
			{
				cout << "User ";
				wcout << username;
				cout << " was successfully deleted from group ";
				wcout << group;
				cout << "\n\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		case 11: // привилегии
		{
			BOOL Status;
			WCHAR name[32];
			cout << "Enter user/group\'s name:\n> ";
			wcin >> name;
			cout << "1 - add privilege, 2 - delete privilege\n> ";
			cin >> mode;
			WCHAR privilege[64];
			cout <<
				"--------------------------- privileges list ---------------------------" << endl <<
				"SeAssignPrimaryTokenPrivilege"     << "\t\t"     <<
				"SeAuditPrivilege"                  << endl       <<
				"SeBackupPrivilege"                 << "\t\t\t"   <<
				"SeChangeNotifyPrivilege"           << endl       <<
				"SeCreateGlobalPrivilege"           << "\t\t\t"   <<
				"SeCreatePagefilePrivilege"         << endl       <<
				"SeCreatePermanentPrivilege"        << "\t\t"     <<
				"SeCreateSymbolicLinkPrivilege"     << endl       <<
				"SeCreateTokenPrivilege"            << "\t\t\t"   <<
				"SeDebugPrivilege"                  << endl       <<
				"SeEnableDelegationPrivilege"       << "\t\t"     <<
				"SeImpersonatePrivilege"            << endl       <<
				"SeIncreaseBasePriorityPrivilege"   << "\t\t"     <<
				"SeIncreaseQuotaPrivilege"          << endl       <<
				"SeIncreaseWorkingSetPrivilege"     << "\t\t"     <<
				"SeLoadDriverPrivilege"             << endl       <<
				"SeLockMemoryPrivilege"             << "\t\t\t"   <<
				"SeMachineAccountPrivilege"         << endl       <<
				"SeManageVolumePrivilege"           << "\t\t\t"   <<
				"SeProfileSingleProcessPrivilege"   << endl       <<
				"SeRelabelPrivilege"                << "\t\t\t"   <<
				"SeRemoteShutdownPrivilege"         << endl       <<
				"SeRestorePrivilege"                << "\t\t\t"   <<
				"SeSecurityPrivilege"               << endl       <<
				"SeShutdownPrivilege"               << "\t\t\t"   <<
				"SeSyncAgentPrivilege"              << endl       <<
				"SeSystemEnvironmentPrivilege"      << "\t\t"     <<
				"SeSystemProfilePrivilege"          << endl       <<
				"SeSystemtimePrivilege"             << "\t\t\t"   <<
				"SeTakeOwnershipPrivilege"          << endl       <<
				"SeTcbPrivilege"                    << "\t\t\t\t" <<
				"SeTimeZonePrivilege"               << endl       <<
				"SeTrustedCredManAccessPrivilege"   << "\t\t"     <<
				"SeUndockPrivilege"                 << endl       <<
				"SeUnsolicitedInputPrivilege"       << "\t\t"     <<
				"SeInteractiveLogonRight"           << endl       <<
				"-----------------------------------------------------------------------" << endl;
			cout << "Enter privilege\n> ";
			wcin >> privilege;

			switch (mode)
			{
			case 1:
			{
				Status = AddPrivilege(name, privilege);
				break;
			}
			case 2:
			{
				Status = RemovePrivilege(name, privilege);
				break;
			}
			default:
			{
				continue;
				break;
			}
			}

			if (Status == TRUE)
			{
				cout << "Privileges were changed\n\n";
			}
			else
			{
				ErrorOutput();
			}
			break;
		}
		default:
		{
			cout << "Wrong input\n";
			break;
		}
		}
	}
}
