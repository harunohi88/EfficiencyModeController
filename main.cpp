// EffModeWatcher_Refined.cpp
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <queue>
#include <algorithm>

#ifndef PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION
#define PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION 0x2
#endif

struct ProcessInfo
{
    DWORD pid = 0;
    DWORD parentPid = 0;
    std::wstring exeName;
};

struct ProcessCacheEntry
{
    bool lastEfficiencyEnabled = false;
    bool hasKnownState = false;
};

static std::wstring ToLower(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

static std::wstring Trim(const std::wstring& s)
{
    const wchar_t* whitespace = L" \t\r\n";
    size_t start = s.find_first_not_of(whitespace);
    if (start == std::wstring::npos)
        return L"";

    size_t end = s.find_last_not_of(whitespace);
    return s.substr(start, end - start + 1);
}

static std::wstring GetLastErrorMessage(DWORD error)
{
    LPWSTR buffer = nullptr;

    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buffer,
        0,
        nullptr
    );

    std::wstring msg = (size && buffer) ? buffer : L"Unknown error";

    if (buffer)
        LocalFree(buffer);

    return msg;
}

static std::unordered_set<std::wstring> LoadWhitelistFromFile(const std::wstring& filePath)
{
    std::unordered_set<std::wstring> whitelist;

    std::wifstream file(filePath);
    file.imbue(std::locale(""));

    if (!file.is_open())
    {
        std::wcerr << L"[WARN] Failed to open whitelist file: " << filePath << L"\n";
        return whitelist;
    }

    std::wstring line;
    while (std::getline(file, line))
    {
        line = Trim(ToLower(line));
        if (!line.empty())
            whitelist.insert(line);
    }

    return whitelist;
}

static std::vector<ProcessInfo> SnapshotProcesses()
{
    std::vector<ProcessInfo> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        std::wcerr << L"[ERROR] CreateToolhelp32Snapshot failed: "
                   << err << L" (" << GetLastErrorMessage(err) << L")\n";
        return processes;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.parentPid = pe.th32ParentProcessID;
            info.exeName = ToLower(pe.szExeFile);
            processes.push_back(info);
        } while (Process32NextW(snapshot, &pe));
    }
    else
    {
        DWORD err = GetLastError();
        std::wcerr << L"[ERROR] Process32FirstW failed: "
                   << err << L" (" << GetLastErrorMessage(err) << L")\n";
    }

    CloseHandle(snapshot);
    return processes;
}

static std::unordered_set<DWORD> FindRootWhitelistPids(
    const std::vector<ProcessInfo>& processes,
    const std::unordered_set<std::wstring>& whitelist)
{
    std::unordered_set<DWORD> roots;

    for (const auto& p : processes)
    {
        if (whitelist.find(p.exeName) != whitelist.end())
            roots.insert(p.pid);
    }

    return roots;
}

static std::unordered_map<DWORD, std::vector<DWORD>> BuildParentToChildrenMap(
    const std::vector<ProcessInfo>& processes)
{
    std::unordered_map<DWORD, std::vector<DWORD>> tree;

    for (const auto& p : processes)
        tree[p.parentPid].push_back(p.pid);

    return tree;
}

static std::unordered_set<DWORD> CollectDescendants(
    const std::unordered_set<DWORD>& rootPids,
    const std::unordered_map<DWORD, std::vector<DWORD>>& parentToChildren)
{
    std::unordered_set<DWORD> result;
    std::queue<DWORD> q;

    for (DWORD rootPid : rootPids)
    {
        result.insert(rootPid);
        q.push(rootPid);
    }

    while (!q.empty())
    {
        DWORD current = q.front();
        q.pop();

        auto it = parentToChildren.find(current);
        if (it == parentToChildren.end())
            continue;

        for (DWORD childPid : it->second)
        {
            if (result.insert(childPid).second)
                q.push(childPid);
        }
    }

    return result;
}

static bool DisableEfficiencyMode(HANDLE hProcess)
{
    PROCESS_POWER_THROTTLING_STATE state{};
    state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    state.ControlMask =
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED |
        PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
    state.StateMask = 0;

    return SetProcessInformation(
        hProcess,
        ProcessPowerThrottling,
        &state,
        sizeof(state)
    ) == TRUE;
}

static std::wstring GetProcessImageName(HANDLE hProcess)
{
    wchar_t buffer[MAX_PATH] = {};
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size))
    {
        std::wstring fullPath(buffer, size);
        size_t pos = fullPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            return fullPath.substr(pos + 1);
        return fullPath;
    }

    return L"<unknown>";
}

static std::wstring FindExeNameByPid(
    DWORD pid,
    const std::unordered_map<DWORD, ProcessInfo>& processMap)
{
    auto it = processMap.find(pid);
    if (it != processMap.end())
        return it->second.exeName;

    return L"<unknown>";
}

static void CleanupDeadCacheEntries(
    std::unordered_map<DWORD, ProcessCacheEntry>& cache,
    const std::unordered_set<DWORD>& aliveTargets)
{
    for (auto it = cache.begin(); it != cache.end(); )
    {
        if (aliveTargets.find(it->first) == aliveTargets.end())
            it = cache.erase(it);
        else
            ++it;
    }
}

static void PatchProcessesByWhitelistTree(
    const std::unordered_set<std::wstring>& whitelist,
    std::unordered_map<DWORD, ProcessCacheEntry>& cache)
{
    auto processes = SnapshotProcesses();
    if (processes.empty())
    {
        std::wcout << L"[INFO] No process snapshot data.\n";
        return;
    }

    std::unordered_map<DWORD, ProcessInfo> processMap;
    processMap.reserve(processes.size());

    for (const auto& p : processes)
        processMap[p.pid] = p;

    auto rootPids = FindRootWhitelistPids(processes, whitelist);
    auto parentToChildren = BuildParentToChildrenMap(processes);
    auto targetPids = CollectDescendants(rootPids, parentToChildren);

    CleanupDeadCacheEntries(cache, targetPids);

    std::wcout << L"[INFO] Root count: " << rootPids.size()
               << L", Target count(with descendants): " << targetPids.size() << L"\n";

    for (DWORD pid : targetPids)
    {
        if (pid == 0 || pid == 4)
            continue;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
            FALSE,
            pid
        );

        if (!hProcess)
        {
            DWORD err = GetLastError();
            std::wcout << L"[SKIP] PID=" << pid
                       << L" " << FindExeNameByPid(pid, processMap)
                       << L" OpenProcess failed: " << err << L")\n";
            continue;
        }

		if (DisableEfficiencyMode(hProcess))
		{
		    std::wcout << L"[PATCHED] PID=" << pid
		               << L" " << GetProcessImageName(hProcess)
		               << L" efficiency mode disable requested\n";
		}
		else
		{
		    DWORD err = GetLastError();
		    std::wcout << L"[FAIL] PID=" << pid
		               << L" " << GetProcessImageName(hProcess)
		               << L" SetProcessInformation failed: " << err << L")\n";
		}

        CloseHandle(hProcess);
    }
}

int wmain()
{
    const std::wstring whitelistPath = L"targets.txt";
    auto whitelist = LoadWhitelistFromFile(whitelistPath);

    if (whitelist.empty())
    {
        std::wcerr << L"[ERROR] Whitelist is empty. Check targets.txt\n";
        return 1;
    }

    std::wcout << L"EffModeWatcher started.\n";
    std::wcout << L"Whitelist file: " << whitelistPath << L"\n";
    std::wcout << L"Watching root processes and descendants every 1000 ms...\n";
    std::wcout << L"Press Ctrl+C to exit.\n\n";

    std::unordered_map<DWORD, ProcessCacheEntry> cache;

    while (true)
    {
        PatchProcessesByWhitelistTree(whitelist, cache);
        std::wcout << L"----------------------------------------\n";
        Sleep(1000);
    }

    return 0;
}
