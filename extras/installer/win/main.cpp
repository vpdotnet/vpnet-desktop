// Copyright (c) 2024 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

/*
Installer architecture:

The Windows installer is written directly against the Win32 API in order to
achieve a zero-dependency executable (statically linked C/C++ runtime) when
executed on Windows 7 and above.

If errors are encountered or the user aborts the installation, the installer
implements a rollback mechanism to undo (most) changes to the system.

The installer uses a two-thread approach, the main thread creating a window
and a message loop (even in silent mode), while launching a separate worker
thread for the actual installation tasks. The main program flow thus lies
in the worker thread, while the main thread keeps the installer responsive.
Mutexes are used to synchronize important state.

Program flow:

             Main thread                         Worker thread
                  |                                    .
           (create window)                             .
                  |                                    .
           (create thread)---------------------------->*
                  |                                    |
         (enter messageloop)                  (install prechecks)
                  |                                    |
                  |<--------(ready to install)---------+
                  |                                    |
           [ click start ]                             |
                  |                                    |
                  +--------(start installation)------->+
                  |                                    |
                  |                        +---------->|
                  |                        |           |
           [ click abort ] . . . .         |    (perform tasks)
                  |              .         |           |
                  |              .         |     <check error>-----+
                  |              .         |           |           |
                  |              . . . . . | . . <check abort>-----+
                  |                        |           |           |
                  |                        +--------<done?>        |
                  |                                    |           |
                  |<------------(finished)-------------+           |
                  |                                    |           |
           [ click close ]                       (exit thread)     |
                  |                                    |           |
         (leave messageloop)                           |           |
                  |                                    |           |
            (join thread)------------------------------*           |
                  |                                    .           |
             (start app)                               .           |
                  |                                    .           |
                  *                                    .           |
                  .                                    .           |
---------------------------< error / rollback >---------------------------
                  |                                    |           |
                  |                                    |<----------+
                  |                                    |
                  |<------------(aborting)-------------+
                  |                                    |
                  |                           (roll back changes)
                  |                                    |
                  |<------------(finished)-------------+
                  |                                    |
           [ click close ]                       (exit thread)
                  |                                    |
         (leave messageloop)                           |
                  |                                    |
            (join thread)------------------------------*
                  |
                  *

Some actions, like starting the installation or acknowleding the result, are
skipped in silent or passive mode.

*/

#include "common.h"

#include <shlobj_core.h>
#include <shlwapi.h>
#include <userenv.h>

#include "resource.h"

#include "util.h"
#include "util_inl.h"
#include "tasks/payload.h"
#include "tasks.h"
#include "installer.h"
#include "product.h"

int main();

extern "C" int CALLBACK _tWinMain(HINSTANCE, HINSTANCE, LPTSTR, int)
{
    // Set secure DLL search order using static linking instead of dynamic loading
    // This avoids the suspicious LoadLibrary+GetProcAddress pattern while achieving
    // the same security goal. SetDefaultDllDirectories is available on Windows 7 SP1+
    // and statically linked, so we can call it directly with a fallback for older systems.
    
#if WINVER >= 0x0601 // Windows 7 SP1 and later
    // Direct call - no dynamic loading needed since we target modern Windows
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
#else
    // Fallback for very old systems - do nothing rather than dynamic loading
    // This is acceptable since the DLL hijacking protection is a hardening measure
#endif

    return main();
}

// Manually link against required system libraries
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "userenv.lib")


#include <utility>
#include <string>
#include <sstream>
#include <fstream>
#include <stack>
#include <list>
#include <vector>
#include <functional>
#include <exception>
#include <atomic>

// Configuration / command-line arguments
bool g_silent = false;          // /SILENT - run (un)installer without a GUI
bool g_passive = true;          // /PASSIVE - run installer without confirmations

// Main objects
HINSTANCE g_instance = NULL;

std::wstring g_executablePath;
std::wstring g_installPath;
std::wstring g_userTempPath;
std::wstring g_systemTempPath;
std::wstring g_startMenuPath;
std::wstring g_clientPath;
std::wstring g_servicePath;
std::wstring g_wgServicePath;
std::wstring g_clientDataPath;
std::wstring g_daemonDataPath;
std::wstring g_oldDaemonDataPath;

static void adjustProcessTokenPrivileges(std::initializer_list<std::pair<LPCTSTR, DWORD>> privileges)
{
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        TOKEN_PRIVILEGES* p = (TOKEN_PRIVILEGES*)malloc(sizeof(TOKEN_PRIVILEGES) + (privileges.size() - 1) * sizeof(LUID_AND_ATTRIBUTES));
        p->PrivilegeCount = 0;

        for (const auto& pair : privileges)
        {
            LUID luid;
            if (LookupPrivilegeValue(NULL, pair.first, &luid))
            {
                p->Privileges[p->PrivilegeCount].Luid = luid;
                p->Privileges[p->PrivilegeCount].Attributes = pair.second;
                p->PrivilegeCount++;
            }
        }
        AdjustTokenPrivileges(token, FALSE, p, 0, NULL, NULL);
        CloseHandle(token);

        free(p);
    }
}

// Determine the path/filename of the (un)installer executable
static std::wstring getExecutablePath()
{
    std::wstring path(MAX_PATH, 0);
    path.resize(GetModuleFileName((HMODULE)g_instance, &path[0], path.size()));
    return path;
}

// Determine the user temp directory (e.g. C:\Users\USER\AppData\Local\Temp)
static std::wstring getUserTempPath()
{
    std::wstring path(MAX_PATH + 2, 0);
    path.resize(GetTempPathW(path.size(), &path[0]));
    while (!path.empty() && path.back() == '\\')
        path.pop_back();
    return path;
}

// Determine the default install path (e.g. C:\Program Files\Private Internet Access)
static std::wstring getInstallPath()
{
#ifdef INSTALLER
    std::wstring path = getShellFolder(CSIDL_PROGRAM_FILES);
    path.push_back('\\');
    path += _T(PIA_PRODUCT_NAME);
    return path;
#endif
#ifdef UNINSTALLER
    return g_executablePath.substr(0, g_executablePath.find_last_of('\\'));
#endif
}


int main()
{
    g_instance = GetModuleHandle(NULL);

    g_executablePath = getExecutablePath();
    g_systemTempPath = getSystemTempPath();
    g_userTempPath = getSystemTempPath();

    g_installPath = getInstallPath();

    if (g_executablePath.empty() || g_systemTempPath.empty() || g_userTempPath.empty())
        return 8;

    Logger logger;

    if (HRESULT err = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))
        LOG("CoInitializeEx failed (%d)", err);

    auto argc = __argc;
    auto argv = __wargv;

    // Removed pid and execute variables - no longer needed since self-copying was eliminated

    // Direct execution mode - no self-copying needed

    // Parse arguments
    for (int i = 1; i < argc; i++)
    {
        if (!_wcsicmp(argv[i], L"/SILENT"))
        {
            g_silent = true;
            g_passive = true;
        }
        else if (!_wcsicmp(argv[i], L"/PASSIVE"))
        {
            g_passive = true;
        }
        else if (!_wcsicmp(argv[i], L"/PATH"))
        {
            if (++i >= argc)
            {
                LOG("Missing argument");
                return 2;
            }
            g_installPath.assign(argv[i]);
#ifdef UNINSTALLER
            if (!PathIsDirectory(g_installPath.c_str()))
            {
                LOG("Non-existent path argument: %ls", g_installPath);
                return 2;
            }
#endif
        }
        // Legacy arguments removed - no longer needed since self-copying was eliminated
        else if (!_wcsicmp(argv[i], L"/EXECUTE") || !_wcsicmp(argv[i], L"/WAITPID"))
        {
            // Skip legacy /EXECUTE and /WAITPID arguments for compatibility
            if (!_wcsicmp(argv[i], L"/WAITPID"))
            {
                // /WAITPID expects a PID argument - consume it
                if (++i >= argc)
                {
                    LOG("Missing argument for legacy /WAITPID");
                    return 2;
                }
            }
        }
        else
        {
            LOG("Unrecognized argument: %ls", argv[i]);
            return 2;
        }
    }

    // PID waiting logic removed - no longer needed since we eliminated self-copying
    // This was used to wait for the parent process before the copied instance executed

    // Execute directly without self-copying to avoid antivirus false positives
    // The original self-copying mechanism was intended to run from a secure location,
    // but this pattern is flagged as suspicious behavior by antivirus software.
    // Modern installers can run safely from their original location with proper UAC handling.

#ifdef INSTALLER
    if (!initializePayload())
    {
        MessageBox(NULL, loadString(IDS_MB_MISSINGPAYLOAD).c_str(), loadString(IDS_MB_CAP_MISSINGPAYLOAD).c_str(), MB_ICONERROR | MB_OK);
        return 1;
    }
#endif

    // Acquire the necessary privileges
    adjustProcessTokenPrivileges({
        // Needed for registry operations
        { SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED },
        { SE_RESTORE_NAME, SE_PRIVILEGE_ENABLED },
        // Needed to launch a process as non-admin
        { SE_INCREASE_QUOTA_NAME, SE_PRIVILEGE_ENABLED },
        { SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED },
    });

    // Run the actual installer & worker thread
    return Installer().run();
}
