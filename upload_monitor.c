// Reduce Windows header bloat and silence MS warnings
#define WIN32_LEAN_AND_MEAN //speeds up compile, avoids unnecessary Win32 junk.
#define _CRT_SECURE_NO_WARNINGS //disables Microsoft’s annoying “secure” warnings.

// Core Windows + ETW headers
#include <windows.h>
#include <evntcons.h>  // ETW consumer structures
#include <tdh.h>     // ETW property decoding

// Networking headers
#include <winsock2.h>
#include <ws2tcpip.h>

// Process info
#include <psapi.h>

// Standard C
#include <stdio.h>
#include <stdlib.h>

// Required libraries
#pragma comment(lib, "advapi32.lib") // ETW control
#pragma comment(lib, "tdh.lib")  // ETW decoding
#pragma comment(lib, "ws2_32.lib")  // Networking

// Kernel ETW provider GUIDs
// These tell Windows what type of events we want
static const GUID FileIoGuid = { 0x90cbdc39, 0x4a3e, 0x11d1, {0x84,0xf4,0x00,0x00,0xf8,0x04,0x64,0xe3} };
static const GUID TcpIpGuid = { 0x9a280ac0, 0xc8e0, 0x11d1, {0x84,0xe2,0x00,0xc0,0x4f,0xb9,0x98,0xa2} };

volatile BOOL g_running = TRUE; // Controls whether the monitor is running

// FileObject → Path table
#define HASH_SIZE 32768
// Hash table entry
typedef struct Entry {
    ULONGLONG key;         // FileObject pointer (unique per file)
    WCHAR path[MAX_PATH];  // Actual file path
    struct Entry* next;    // For hash collisions
} Entry;

// Hash table + lock
Entry* table[HASH_SIZE] = { 0 };
CRITICAL_SECTION cs_table;

// Per-PID tracking // Tracks file activity per process
#define PID_SLOTS 8192
typedef struct {
    DWORD  pid;
    WCHAR  path[MAX_PATH];
    DWORD  bytes;
    DWORD  tick;
} FileSlot;
// Tracks network activity per process
typedef struct {
    DWORD  pid;
    WCHAR  ip[64];
    USHORT port;
    DWORD  bytes;
    DWORD  tick;
} NetSlot;

FileSlot fslots[PID_SLOTS] = { 0 };
NetSlot  nslots[PID_SLOTS] = { 0 };

// Simple hash
static DWORD hash(ULONGLONG k) { return (DWORD)(k ^ (k >> 32)) % HASH_SIZE; }

// Save file path when file is opened/created
void store_path(ULONGLONG key, const WCHAR* p) {
    if (!p || !p[0]) return;
    EnterCriticalSection(&cs_table);
    DWORD h = hash(key);
    Entry** pp = &table[h];

    // Update if already exists
    while (*pp) {
        if ((*pp)->key == key) { wcscpy_s((*pp)->path, MAX_PATH, p); LeaveCriticalSection(&cs_table); return; }
        pp = &(*pp)->next;
    }

    // Insert new entry
    Entry* e = malloc(sizeof(Entry));
    if (e) {
        e->key = key;
        wcscpy_s(e->path, MAX_PATH, p);
        e->next = NULL;
        *pp = e;
    }
    LeaveCriticalSection(&cs_table);
}

 // Retrieve file path during file read
BOOL get_path(ULONGLONG key, WCHAR* out) {
    EnterCriticalSection(&cs_table);
    Entry* e = table[hash(key)];
    while (e) {
        if (e->key == key) {
            wcscpy_s(out, MAX_PATH, e->path);
            LeaveCriticalSection(&cs_table);
            return TRUE;
        }
        e = e->next;
    }
    LeaveCriticalSection(&cs_table);
    return FALSE;
}

// Helpers (ETW data is raw; these extract values safely).
static BOOL GetU64(PEVENT_RECORD r, LPCWSTR n, ULONGLONG* v) {
    PROPERTY_DATA_DESCRIPTOR d = { (ULONG64)n };
    ULONG sz = sizeof(*v);
    return TdhGetProperty(r, 0, NULL, 1, &d, sz, (PBYTE)v) == ERROR_SUCCESS;
}
static BOOL GetU32(PEVENT_RECORD r, LPCWSTR n, ULONG* v) {
    PROPERTY_DATA_DESCRIPTOR d = { (ULONG64)n };
    ULONG sz = sizeof(*v);
    return TdhGetProperty(r, 0, NULL, 1, &d, sz, (PBYTE)v) == ERROR_SUCCESS;
}
static BOOL GetU16(PEVENT_RECORD r, LPCWSTR n, USHORT* v) {
    PROPERTY_DATA_DESCRIPTOR d = { (ULONG64)n };
    ULONG sz = sizeof(*v);
    return TdhGetProperty(r, 0, NULL, 1, &d, sz, (PBYTE)v) == ERROR_SUCCESS;
}
static BOOL GetStr(PEVENT_RECORD r, LPCWSTR n, WCHAR* buf, int chars) {
    PROPERTY_DATA_DESCRIPTOR d = { (ULONG64)n };
    ULONG sz = 0;
    if (TdhGetPropertySize(r, 0, NULL, 1, &d, &sz) != ERROR_SUCCESS) return FALSE;
    if (sz > chars * sizeof(WCHAR)) sz = chars * sizeof(WCHAR);
    return TdhGetProperty(r, 0, NULL, 1, &d, sz, (PBYTE)buf) == ERROR_SUCCESS;
}

// Final detection logic
static void detect(DWORD pid) {
    DWORD idx = pid % PID_SLOTS;
    FileSlot* f = &fslots[idx];
    NetSlot* n = &nslots[idx];
    if (f->pid != pid || n->pid != pid) return;   // Must belong to same process

    // 8 KB minimum – catches even WhatsApp images
    if (f->bytes < 8192 || n->bytes < 8192) return;

    DWORD now = GetTickCount();
    DWORD diff = (f->tick > n->tick) ? (f->tick - n->tick) : (n->tick - f->tick);
    if (diff > 20000) return;  // 20 sec window

    WCHAR proc[MAX_PATH] = { 0 }; // Get process name
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) { GetModuleBaseNameW(h, NULL, proc, MAX_PATH); CloseHandle(h); }

    SYSTEMTIME st; GetLocalTime(&st);  // Print upload alert
    wprintf(L"\nUPLOAD DETECTED [%04d-%02d-%02d %02d:%02d:%02d]\n"
        L"  Process : %s (PID %lu)\n"
        L"  File    : %s\n"
        L"  Target  : %s:%u\n"
        L"  Size    : %u → %u bytes\n"
        L"  ──────────────────────────────────────\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        proc, pid, f->path, n->ip, n->port, f->bytes, n->bytes);

    // Log to file
    FILE* log = NULL;
    _wfopen_s(&log, L"uploads.log", L"a, ccs=UTF-8");
    if (log) {
        fwprintf(log, L"[%04d-%02d-%02d %02d:%02d:%02d] %s | %s → %s:%u | %u bytes\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            proc, f->path, n->ip, n->port, f->bytes);
        fclose(log);
    }

    // reset
    f->bytes = 0;
    n->bytes = 0;
}

VOID WINAPI EventCallback(PEVENT_RECORD rec) {
    if (!g_running) return;
    DWORD pid = rec->EventHeader.ProcessId;
    if (pid <= 4) return;

    // FILE I/O
    if (IsEqualGUID(&rec->EventHeader.ProviderId, &FileIoGuid)) {
        USHORT op = rec->EventHeader.EventDescriptor.Opcode;

        if (op == 0 || op == 32 || op == 36) {  // File open/create → store path
            ULONGLONG key = 0;
            WCHAR path[MAX_PATH] = { 0 };
            if (GetU64(rec, L"FileObject", &key) && GetStr(rec, L"FileName", path, MAX_PATH)) {
                store_path(key, path);
            }
        }

        // Read OR OpEnd (this is the magic line!)
        if (op == 64 || op == 67) {
            ULONGLONG key = 0;
            ULONG size = 0;
            if (!GetU64(rec, L"FileObject", &key)) return;
            if (!GetU32(rec, L"IoSize", &size)) return;
            if (size == 0) return;

            WCHAR path[MAX_PATH] = L"<unknown>";
            get_path(key, path);

            // skip junk
            if (wcsstr(path, L"\\Windows\\") || wcsstr(path, L"\\Program Files") || wcsstr(path, L"\\AppData\\Local\\Temp")) return;

            DWORD i = pid % PID_SLOTS;
            fslots[i].pid = pid;
            wcscpy_s(fslots[i].path, MAX_PATH, path);
            fslots[i].bytes += size;
            fslots[i].tick = GetTickCount();
        }
    }

    // NETWORK
    else if (IsEqualGUID(&rec->EventHeader.ProviderId, &TcpIpGuid)) {
        if (rec->EventHeader.EventDescriptor.Id == 10) {   // Event ID 10 = TCP send
            ULONG size = 0, addr = 0;
            USHORT port = 0;
            if (!GetU32(rec, L"size", &size)) return;
            if (!GetU32(rec, L"daddr", &addr)) return;
            if (!GetU16(rec, L"dport", &port)) return;

            BYTE* b = (BYTE*)&addr;    // Ignore private IPs
            if (b[0] == 10 || (b[0] == 192 && b[1] == 168) || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)) return;

            WCHAR ip[64];
            wsprintfW(ip, L"%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

            DWORD i = pid % PID_SLOTS;
            nslots[i].pid = pid;
            wcscpy_s(nslots[i].ip, 64, ip);
            nslots[i].port = ntohs(port);
            nslots[i].bytes += size;
            nslots[i].tick = GetTickCount();

            detect(pid);   // Try detecting upload
        }
    }
}

int main() {
    SetConsoleTitleW(L"REAL-TIME UPLOAD MONITOR 2025 – CLOSE TO STOP");
    wprintf(L"Starting monitor... Run as Administrator!\n\n");
    InitializeCriticalSection(&cs_table);
    // Configure kernel ETW session
    ULONG sz = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAMEW);
    EVENT_TRACE_PROPERTIES* p = malloc(sz);
    ZeroMemory(p, sz);
    p->Wnode.BufferSize = sz;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p->EnableFlags = EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_NETWORK_TCPIP;
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    TRACEHANDLE sess = 0;
    if (StartTraceW(&sess, KERNEL_LOGGER_NAMEW, p) != ERROR_SUCCESS &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        wprintf(L"StartTrace failed\n");
        return 1;
    }

    EVENT_TRACE_LOGFILEW log = { 0 };
    log.LoggerName = KERNEL_LOGGER_NAMEW;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventCallback;

    TRACEHANDLE h = OpenTraceW(&log);
    if (h == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"OpenTrace failed\n");
        return 1;
    }

    wprintf(L"MONITORING LIVE – Upload any file now!\n\n");
    ProcessTrace(&h, 1, NULL, NULL);

    // cleanup
    CloseTrace(h);
    ControlTraceW(sess, KERNEL_LOGGER_NAMEW, p, EVENT_TRACE_CONTROL_STOP);
    free(p);
    DeleteCriticalSection(&cs_table);
    return 0;
}