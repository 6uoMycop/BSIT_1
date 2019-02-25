#include <iostream>
#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <ntsecapi.h> 

#pragma comment(lib, "netapi32.lib")

using namespace std;

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

	nStatus = NetUserEnum(
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
			NetUserGetInfo((LPCWSTR)pszServerName, pTmpBuf->usri0_name, 4, (LPBYTE*)&pTmpBuf1);
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

			NetUserGetGroups((LPCWSTR)pszServerName, pTmpBuf->usri0_name, 1, (LPBYTE*)&pBuf1, MAX_PREFERRED_LENGTH, &dwEntriesRead1, &dwTotalEntries);
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

			nStatus = NetUserGetLocalGroups((LPCWSTR)pszServerName, pTmpBuf->usri0_name, 0, dwFlags, (LPBYTE *)&pBuf2, MAX_PREFERRED_LENGTH, &dwEntriesRead1, &dwTotalEntries);

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

	dwError = NetUserAdd(
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

	nStatus = NetUserDel(pszServerName, wAccount);
	
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

	nStatus = NetUserSetInfo(pszServerName, wName, 0, (LPBYTE)uiName, 0);
	if (nStatus != NERR_Success)
	{
		SetLastError(nStatus);
		return FALSE;
	}

	nStatus = NetUserSetInfo(pszServerName, wNewName, 1003, (LPBYTE)uiPass, 0);
	if (nStatus != NERR_Success)
	{
		SetLastError(nStatus);
		return FALSE;
	}

	return TRUE;
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
	nStatus = NetGroupEnum((LPCWSTR)pszServerName, 0, (LPBYTE *)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
	if (nStatus == NERR_Success)
	{
		LPGROUP_INFO_0 pTmpBuf;

		if ((pTmpBuf = pBuf) != NULL)
		{
			printf("Global group_s:\n");

			for (unsigned int i = 0; i < dwEntriesRead; i++)
			{

				if (pTmpBuf == NULL)
				{
					fprintf(stderr, "An access violation has occurred\n");
					break;
				}

				wprintf(L"Name:\t\t%s\n\n", pTmpBuf->grpi0_name);
				
				pTmpBuf++;
			}
		}
	}

	LPLOCALGROUP_INFO_1 pBuf1;
	nStatus = NetLocalGroupEnum((LPCWSTR)pszServerName, 1, (LPBYTE *)&pBuf1, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
	if (nStatus == NERR_Success)
	{
		LPLOCALGROUP_INFO_1 pTmpBuf1;

		if ((pTmpBuf1 = pBuf1) != NULL)
		{
			printf("Local group_s:\n");

			for (unsigned int i = 0; i < dwEntriesRead; i++)
			{
				if (pTmpBuf1 == NULL)
				{
					fprintf(stderr, "An access violation has occurred\n");
					break;
				}
				wprintf(L"Name:\t\t%s\nComment:\t%s\n\n", pTmpBuf1->lgrpi1_name, pTmpBuf1->lgrpi1_comment);
				pTmpBuf1++;
			}
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

	nStatus = NetGroupAdd(pszServerName, 0, (LPBYTE)pBuf, 0);

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

	nStatus = NetLocalGroupAdd(pszServerName, 0, (LPBYTE)pBuf, 0);

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

	nStatus = NetGroupDel(pszServerName, wName);

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

	nStatus = NetLocalGroupDel(pszServerName, wName);

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
	LPGROUP_INFO_1 pBuf = new GROUP_INFO_1;
	pBuf->grpi1_name = wNewName;
	pBuf->grpi1_comment = wNewComment;
	NET_API_STATUS nStatus;

	nStatus = NetGroupSetInfo(pszServerName, wName, 1, (LPBYTE)pBuf, 0);

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
	LPLOCALGROUP_INFO_1 pBuf = new LOCALGROUP_INFO_1;
	pBuf->lgrpi1_name = wNewName;
	pBuf->lgrpi1_comment = wNewComment;
	NET_API_STATUS nStatus;

	nStatus = NetLocalGroupSetInfo(pszServerName, wName, 1, (LPBYTE)pBuf, 0);

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

	nStatus = NetGroupAddUser(pszServerName, wGroup, wUsername);

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

	nStatus = NetLocalGroupAddMembers(pszServerName, wGroup, 3, (LPBYTE)pBuf, 1);

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

	nStatus = NetGroupDelUser(pszServerName, wGroup, wUsername);

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
	nStatus = NetLocalGroupDelMembers(pszServerName, wGroup, 3, (LPBYTE)pBuf, 1);

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
				"SeAssignPrimaryTokenPrivilege"		<< "\t\t"     <<
				"SeAuditPrivilege"                  << endl       <<
				"SeBackupPrivilege"					<< "\t\t\t"   <<
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
