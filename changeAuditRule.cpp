HANDLE hProcess = GetCurrentProcess();
HANDLE hToken;
DWORD val;
BOOL result;
result = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
if (result == 0)
{
    printf("\nBreak After open process");   
    return 0;
}
else{
    printf("\ncontinue after open process");
}
// Used for reading SACL's
result = SetPrivilege(hToken, SE_SECURITY_NAME, TRUE);
if (result == 0)
{
    printf("\nBreak After setprivilege");   
    return 0;
}
else{
    printf("\ncontinue after open process");
}
CloseHandle(hToken);
retval = GetNamedSecurityInfo(file, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, &owner, NULL, NULL, &sacl, &psd);
if(retval != 0)
{
     wcout << "GetNamedSecurityInfo failed with error: " << retval << endl;
     return -1;
}
printf("\nBuilt trust successfully before");
BuildTrusteeWithSid(ptrust,psd);
printf("\nBuilt trust successfully");


printf("\ntrying to modify ...");
EXPLICIT_ACCESS ea;
PACL pNewSACL = NULL;
ACCESS_MODE AccessMode =  SET_AUDIT_SUCCESS; //SET_AUDIT_SUCCESS, SET_AUDIT_FAILURE
DWORD dwAccessRights = 0X410D0060;
DWORD dwInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

ea.grfAccessPermissions = dwAccessRights;
ea.grfAccessMode = SET_AUDIT_SUCCESS;
ea.grfInheritance = dwInheritance;
ea.Trustee = *(ptrust); 



DWORD dwRes = SetEntriesInAcl(1, &ea, sacl, &pNewSACL);
if(dwRes != ERROR_SUCCESS)
{
    printf("SetEntriesInAcl() error %u\n", dwRes);
}
else
{
    printf("SetEntriesInAcl() is OK\n");
}

dwRes = SetNamedSecurityInfo(file, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, pNewSACL);
if(dwRes != ERROR_SUCCESS)
{
    printf("SetNamedSecurityInfo() error %u\n", dwRes);

}
else
    printf("SetNamedSecurityInfo() is OK\n\n");


LocalFree(psd);
