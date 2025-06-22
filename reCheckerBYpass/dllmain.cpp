#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <psapi.h>
#include "detours.h"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "psapi.lib")

#define MAX_HIDDEN_FILES 100
#define MAX_FILENAME_LENGTH 260

class EngineLogger {
private:
    DWORD engine_base;
    DWORD steam_api_base;
    static const DWORD LOGGING_FUNC_OFFSET = 0x2CB40;
    static const DWORD COLORED_LOGGING_FUNC_OFFSET = 0x1A2DC8;

public:
    EngineLogger() : engine_base(0), steam_api_base(0) {
        initialize();
    }

    bool initialize() {
        engine_base = (DWORD)GetModuleHandleA("engine.dll");
        steam_api_base = (DWORD)GetModuleHandleA("steam_api.dll");
        return engine_base != 0;
    }

    bool send_log(const char* format, ...) {
        if (!engine_base) return false;

        char buffer[1024];
        va_list args;
        va_start(args, format);
        _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
        va_end(args);
        buffer[sizeof(buffer) - 1] = '\0';

        typedef void(__cdecl* LoggingFunc)(const char*);
        LoggingFunc logging_func = (LoggingFunc)(engine_base + LOGGING_FUNC_OFFSET);

        __try {
            logging_func(buffer);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool send_colored_log(const char* format, ...) {
        if (!steam_api_base) return false;

        char buffer[1024];
        va_list args;
        va_start(args, format);
        _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
        va_end(args);
        buffer[sizeof(buffer) - 1] = '\0';

        DWORD* func_ptr_addr = (DWORD*)(steam_api_base + COLORED_LOGGING_FUNC_OFFSET);

        __try {
            DWORD func_addr = *func_ptr_addr;
            if (func_addr == 0) return false;

            typedef void(__cdecl* ColoredLoggingFunc)(const char*, ...);
            ColoredLoggingFunc colored_logging_func = (ColoredLoggingFunc)func_addr;

            colored_logging_func("%s", buffer);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool ShouldShowScan(const char* filename) {
        if (!filename) return false;

        const char* ext = strrchr(filename, '.');
        if (!ext) return true;

        return !(_stricmp(ext, ".tga") == 0 ||
            _stricmp(ext, ".spr") == 0 ||
            _stricmp(ext, ".bsp") == 0 ||
            _stricmp(ext, ".mdl") == 0 ||
            _stricmp(ext, ".sc") == 0 ||
            _stricmp(ext, ".wad") == 0 ||
            _stricmp(ext, ".wav") == 0 ||
            _stricmp(ext, ".res") == 0);
    }

    void log_file_access(const char* filename, bool is_hidden) {
        if (!filename) return;

        if (is_hidden) {
            if (!send_colored_log("${red}[BLOCKED]${white} %s\n", filename)) {
                send_log("[BLOCKED] %s\n", filename);
            }
        }
        else {
            if (ShouldShowScan(filename)) {
                if (!send_colored_log("${springgreen}[SCAN]${white} %s\n", filename)) {
                    send_log("[SCAN] %s\n", filename);
                }
            }
        }
    }

    void log_startup_message() {
        if (!send_colored_log("${yellow}ReChecker Bypass by Linkmail ${springgreen}LOADED${white}\n")) {
            send_log("ReChecker Bypass by Linkmail LOADED\n");
        }
    }

    void log_scan_complete(int total_files, int interesting_files) {
        if (!send_colored_log("${cyan}[SCAN]${white} Archivos indexados: %d | Relevantes: %d\n", total_files, interesting_files)) {
            send_log("[SCAN] Archivos indexados: %d | Relevantes: %d\n", total_files, interesting_files);
        }
    }

    void log_config_loaded(int patterns_count) {
        if (!send_colored_log("${cyan}[CONFIG]${white} Cargados %d patrones desde hiddenFiles.cfg\n", patterns_count)) {
            send_log("[CONFIG] Cargados %d patrones desde hiddenFiles.cfg\n", patterns_count);
        }
    }
};

class FileSystemHook;
static FileSystemHook* g_fs_hook = nullptr;
static EngineLogger* g_logger = nullptr;

class FileSystemHook {
public:
    static int total_file_checks;
    static int hidden_file_count;

private:
    char files_to_hide[MAX_HIDDEN_FILES][MAX_FILENAME_LENGTH];
    int files_to_hide_count;
    static const char* CONFIG_FILE_NAME;

    struct FileEntry {
        char filename[260];
        bool exists;
        bool is_interesting;
    };

    static FileEntry file_cache[2000];
    static int cache_size;

    struct LogThrottle {
        char filename[260];
        DWORD last_log_time;
        bool is_hidden;
    };

    static LogThrottle log_cache[100];
    static int log_count;
    static const DWORD LOG_THROTTLE_MS = 10000;

    typedef HANDLE(WINAPI* CreateFileAFunc)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef HANDLE(WINAPI* CreateFileWFunc)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL(WINAPI* GetFileAttributesExAFunc)(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
    typedef BOOL(WINAPI* GetFileAttributesExWFunc)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
    typedef DWORD(WINAPI* GetFileAttributesAFunc)(LPCSTR);
    typedef DWORD(WINAPI* GetFileAttributesWFunc)(LPCWSTR);
    typedef BOOL(WINAPI* PathFileExistsAFunc)(LPCSTR);
    typedef BOOL(WINAPI* PathFileExistsWFunc)(LPCWSTR);
    typedef FILE* (CDECL* FopenFunc)(const char*, const char*);

    CreateFileAFunc original_CreateFileA;
    CreateFileWFunc original_CreateFileW;
    GetFileAttributesExAFunc original_GetFileAttributesExA;
    GetFileAttributesExWFunc original_GetFileAttributesExW;
    GetFileAttributesAFunc original_GetFileAttributesA;
    GetFileAttributesWFunc original_GetFileAttributesW;
    PathFileExistsAFunc original_PathFileExistsA;
    PathFileExistsWFunc original_PathFileExistsW;
    FopenFunc original_fopen;

    void CreateDefaultConfig() {
        FILE* config = fopen(CONFIG_FILE_NAME, "w");
        if (config) {
            fprintf(config, "# ReChecker Bypass - Archivo de configuracion\n");
            fprintf(config, "# Cada linea representa un archivo o patron a ocultar\n");
            fprintf(config, "# Usa * como wildcard para coincidir con cualquier texto\n");
            fprintf(config, "# Ejemplos:\n");
            fprintf(config, "#   archivo.dll      - Oculta exactamente 'archivo.dll'\n");
            fprintf(config, "#   *hack.dll        - Oculta cualquier archivo que termine en 'hack.dll'\n");
            fprintf(config, "#   hack*            - Oculta cualquier archivo que empiece con 'hack'\n");
            fprintf(config, "#   *hack*           - Oculta cualquier archivo que contenga 'hack'\n");
            fprintf(config, "# Las lineas que empiezan con # son comentarios\n");
            fprintf(config, "\n");
            fprintf(config, "# Archivos a ocultar:\n");
            fprintf(config, "hiddenFiles.cfg\n");
            fprintf(config, "psgs.cfg\n");
            fclose(config);
        }
    }

    void LoadConfig() {
        files_to_hide_count = 0;

        FILE* test = fopen(CONFIG_FILE_NAME, "r");
        if (!test) {
            CreateDefaultConfig();
        }
        else {
            fclose(test);
        }

        FILE* config = fopen(CONFIG_FILE_NAME, "r");
        if (config) {
            char line[MAX_FILENAME_LENGTH];
            while (fgets(line, sizeof(line), config) && files_to_hide_count < MAX_HIDDEN_FILES) {
                size_t len = strlen(line);
                if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                    line[len - 1] = '\0';
                    if (len > 1 && (line[len - 2] == '\n' || line[len - 2] == '\r')) {
                        line[len - 2] = '\0';
                    }
                }

                char* start = line;
                while (*start == ' ' || *start == '\t') start++;

                if (*start && *start != '#') {
                    strncpy(files_to_hide[files_to_hide_count], start, MAX_FILENAME_LENGTH - 1);
                    files_to_hide[files_to_hide_count][MAX_FILENAME_LENGTH - 1] = '\0';
                    _strlwr(files_to_hide[files_to_hide_count]);
                    files_to_hide_count++;
                }
            }
            fclose(config);

            if (g_logger) {
                g_logger->log_config_loaded(files_to_hide_count);
            }
        }
    }

    bool MatchesPattern(const char* filename, const char* pattern) {
        const char* f = filename;
        const char* p = pattern;
        const char* star_p = NULL;
        const char* star_f = NULL;

        while (*f) {
            if (*p == *f || *p == '?') {
                f++;
                p++;
            }
            else if (*p == '*') {
                star_p = p++;
                star_f = f;
            }
            else if (star_p) {
                p = star_p + 1;
                f = ++star_f;
            }
            else {
                return false;
            }
        }

        while (*p == '*') p++;
        return !*p;
    }

    bool IsInterestingFile(const char* filename) {
        if (!filename) return false;

        const char* ext = strrchr(filename, '.');
        if (!ext) return false;

        return (_stricmp(ext, ".dll") == 0 ||
            _stricmp(ext, ".cfg") == 0 ||
            _stricmp(ext, ".ini") == 0 ||
            _stricmp(ext, ".asi") == 0);
    }

    void ScanDirectory(const char* path) {
        WIN32_FIND_DATAA findData;
        char searchPath[520];
        _snprintf(searchPath, 520, "%s\\*", path);
        searchPath[519] = '\0';

        HANDLE hFind = FindFirstFileA(searchPath, &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    if (_stricmp(findData.cFileName, "cstrike") == 0) {
                        char subPath[520];
                        _snprintf(subPath, 520, "%s\\%s", path, findData.cFileName);
                        subPath[519] = '\0';
                        ScanDirectory(subPath);
                    }
                }
            }
            else {
                if (cache_size < 2000) {
                    strncpy(file_cache[cache_size].filename, findData.cFileName, 259);
                    file_cache[cache_size].filename[259] = '\0';
                    file_cache[cache_size].exists = true;
                    file_cache[cache_size].is_interesting = IsInterestingFile(findData.cFileName);
                    cache_size++;
                }
            }
        } while (FindNextFileA(hFind, &findData) != 0);

        FindClose(hFind);
    }

    bool FileExistsInCache(const char* filename) {
        if (!filename) return false;

        for (int i = 0; i < cache_size; i++) {
            if (_stricmp(file_cache[i].filename, filename) == 0) {
                return file_cache[i].exists && file_cache[i].is_interesting;
            }
        }
        return false;
    }

    const char* GetFilenameFromPath(const char* path) {
        if (!path) return nullptr;

        const char* filename = strrchr(path, '\\');
        if (filename) {
            return filename + 1;
        }

        filename = strrchr(path, '/');
        if (filename) {
            return filename + 1;
        }

        return path;
    }

    bool ShouldLogFile(const char* fullpath, bool is_hidden) {
        if (!fullpath) return false;

        const char* filename = GetFilenameFromPath(fullpath);
        if (!filename) return false;

        DWORD current_time = GetTickCount();

        for (int i = 0; i < log_count; i++) {
            if (_stricmp(log_cache[i].filename, filename) == 0 && log_cache[i].is_hidden == is_hidden) {
                if (current_time - log_cache[i].last_log_time < LOG_THROTTLE_MS) {
                    return false;
                }
                else {
                    log_cache[i].last_log_time = current_time;
                    return true;
                }
            }
        }

        if (log_count < 100) {
            strncpy(log_cache[log_count].filename, filename, 259);
            log_cache[log_count].filename[259] = '\0';
            log_cache[log_count].last_log_time = current_time;
            log_cache[log_count].is_hidden = is_hidden;
            log_count++;
            return true;
        }

        int oldest_index = 0;
        DWORD oldest_time = log_cache[0].last_log_time;
        for (int i = 1; i < 100; i++) {
            if (log_cache[i].last_log_time < oldest_time) {
                oldest_time = log_cache[i].last_log_time;
                oldest_index = i;
            }
        }

        strncpy(log_cache[oldest_index].filename, filename, 259);
        log_cache[oldest_index].filename[259] = '\0';
        log_cache[oldest_index].last_log_time = current_time;
        log_cache[oldest_index].is_hidden = is_hidden;
        return true;
    }

    bool IsPsgFile(const char* filename) {
        if (!filename || !*filename) return false;

        const char* name_only = GetFilenameFromPath(filename);
        if (!name_only) name_only = filename;

        char lower_name[MAX_FILENAME_LENGTH];
        strncpy(lower_name, name_only, MAX_FILENAME_LENGTH - 1);
        lower_name[MAX_FILENAME_LENGTH - 1] = '\0';
        _strlwr(lower_name);

        for (int i = 0; i < files_to_hide_count; i++) {
            if (MatchesPattern(lower_name, files_to_hide[i])) {
                return true;
            }
        }

        return false;
    }

    bool IsPsgFile(const wchar_t* filename) {
        if (!filename || !*filename) return false;

        char narrow_filename[260];
        WideCharToMultiByte(CP_UTF8, 0, filename, -1, narrow_filename, 260, nullptr, nullptr);

        return IsPsgFile(narrow_filename);
    }

    void LogFileAccess(const char* fullpath, bool is_hidden) {
        total_file_checks++;
        if (is_hidden) {
            hidden_file_count++;
            if (g_logger && ShouldLogFile(fullpath, is_hidden)) {
                const char* filename = GetFilenameFromPath(fullpath);
                g_logger->log_file_access(filename ? filename : fullpath, is_hidden);
            }
        }
        else {
            const char* filename = GetFilenameFromPath(fullpath);
            if (filename && g_logger && g_logger->ShouldShowScan(filename) && ShouldLogFile(fullpath, is_hidden)) {
                g_logger->log_file_access(filename, is_hidden);
            }
        }
    }

    void LogFileAccess(const wchar_t* fullpath, bool is_hidden) {
        char narrow_filename[260];
        WideCharToMultiByte(CP_UTF8, 0, fullpath, -1, narrow_filename, 260, nullptr, nullptr);
        LogFileAccess(narrow_filename, is_hidden);
    }

public:
    FileSystemHook() :
        original_CreateFileA(nullptr),
        original_CreateFileW(nullptr),
        original_GetFileAttributesExA(nullptr),
        original_GetFileAttributesExW(nullptr),
        original_GetFileAttributesA(nullptr),
        original_GetFileAttributesW(nullptr),
        original_PathFileExistsA(nullptr),
        original_PathFileExistsW(nullptr),
        original_fopen(nullptr),
        files_to_hide_count(0) {
        memset(files_to_hide, 0, sizeof(files_to_hide));
    }

    void ScanGameFiles() {
        char game_dir[260];
        if (GetCurrentDirectoryA(260, game_dir) == 0) return;

        cache_size = 0;
        ScanDirectory(game_dir);

        int interesting_count = 0;
        for (int i = 0; i < cache_size; i++) {
            if (file_cache[i].is_interesting) {
                interesting_count++;
            }
        }

        if (g_logger) {
            g_logger->log_scan_complete(cache_size, interesting_count);
        }
    }

    static HANDLE WINAPI Hooked_CreateFileA(
        LPCSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile) {

        if (g_fs_hook && lpFileName) {
            bool is_psg = g_fs_hook->IsPsgFile(lpFileName);
            g_fs_hook->LogFileAccess(lpFileName, is_psg);

            if (is_psg) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
        }

        return g_fs_hook->original_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
            lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    static HANDLE WINAPI Hooked_CreateFileW(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile) {

        if (g_fs_hook && lpFileName) {
            bool is_psg = g_fs_hook->IsPsgFile(lpFileName);
            g_fs_hook->LogFileAccess(lpFileName, is_psg);

            if (is_psg) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
        }

        return g_fs_hook->original_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
            lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    static BOOL WINAPI Hooked_GetFileAttributesExA(
        LPCSTR lpFileName,
        GET_FILEEX_INFO_LEVELS fInfoLevelId,
        LPVOID lpFileInformation) {

        if (g_fs_hook && lpFileName) {
            bool is_psg = g_fs_hook->IsPsgFile(lpFileName);
            g_fs_hook->LogFileAccess(lpFileName, is_psg);

            if (is_psg) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                return FALSE;
            }
        }

        return g_fs_hook->original_GetFileAttributesExA(lpFileName, fInfoLevelId, lpFileInformation);
    }

    static BOOL WINAPI Hooked_GetFileAttributesExW(
        LPCWSTR lpFileName,
        GET_FILEEX_INFO_LEVELS fInfoLevelId,
        LPVOID lpFileInformation) {

        if (g_fs_hook && lpFileName) {
            bool is_psg = g_fs_hook->IsPsgFile(lpFileName);
            g_fs_hook->LogFileAccess(lpFileName, is_psg);

            if (is_psg) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                return FALSE;
            }
        }

        return g_fs_hook->original_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
    }

    static DWORD WINAPI Hooked_GetFileAttributesA(LPCSTR lpFileName) {
        if (g_fs_hook && lpFileName) {
            bool is_psg = g_fs_hook->IsPsgFile(lpFileName);
            g_fs_hook->LogFileAccess(lpFileName, is_psg);

            if (is_psg) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                return INVALID_FILE_ATTRIBUTES;
            }
        }

        return g_fs_hook->original_GetFileAttributesA(lpFileName);
    }

    static DWORD WINAPI Hooked_GetFileAttributesW(LPCWSTR lpFileName) {
        if (g_fs_hook && lpFileName) {
            bool is_psg = g_fs_hook->IsPsgFile(lpFileName);
            g_fs_hook->LogFileAccess(lpFileName, is_psg);

            if (is_psg) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                return INVALID_FILE_ATTRIBUTES;
            }
        }

        return g_fs_hook->original_GetFileAttributesW(lpFileName);
    }

    static BOOL WINAPI Hooked_PathFileExistsA(LPCSTR pszPath) {
        if (g_fs_hook && pszPath) {
            bool is_psg = g_fs_hook->IsPsgFile(pszPath);
            g_fs_hook->LogFileAccess(pszPath, is_psg);

            if (is_psg) {
                return FALSE;
            }
        }

        return g_fs_hook->original_PathFileExistsA(pszPath);
    }

    static BOOL WINAPI Hooked_PathFileExistsW(LPCWSTR pszPath) {
        if (g_fs_hook && pszPath) {
            bool is_psg = g_fs_hook->IsPsgFile(pszPath);
            g_fs_hook->LogFileAccess(pszPath, is_psg);

            if (is_psg) {
                return FALSE;
            }
        }

        return g_fs_hook->original_PathFileExistsW(pszPath);
    }

    static FILE* __cdecl Hooked_fopen(const char* filename, const char* mode) {
        if (g_fs_hook && filename) {
            bool is_psg = g_fs_hook->IsPsgFile(filename);
            g_fs_hook->LogFileAccess(filename, is_psg);

            if (is_psg) {
                errno = ENOENT;
                return nullptr;
            }
        }

        return g_fs_hook->original_fopen(filename, mode);
    }

    bool initialize() {
        original_CreateFileA = CreateFileA;
        original_CreateFileW = CreateFileW;
        original_GetFileAttributesExA = GetFileAttributesExA;
        original_GetFileAttributesExW = GetFileAttributesExW;
        original_GetFileAttributesA = GetFileAttributesA;
        original_GetFileAttributesW = GetFileAttributesW;

        HMODULE shlwapi = LoadLibraryA("shlwapi.dll");
        if (shlwapi) {
            original_PathFileExistsA = (PathFileExistsAFunc)GetProcAddress(shlwapi, "PathFileExistsA");
            original_PathFileExistsW = (PathFileExistsWFunc)GetProcAddress(shlwapi, "PathFileExistsW");
        }

        HMODULE msvcrt = GetModuleHandleA("msvcrt.dll");
        if (!msvcrt) msvcrt = GetModuleHandleA("ucrtbase.dll");
        if (msvcrt) {
            original_fopen = (FopenFunc)GetProcAddress(msvcrt, "fopen");
        }

        LoadConfig();

        return true;
    }

    bool install_hooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        bool success = true;

        if (DetourAttach(&(PVOID&)original_CreateFileA, Hooked_CreateFileA) != NO_ERROR) success = false;
        if (DetourAttach(&(PVOID&)original_CreateFileW, Hooked_CreateFileW) != NO_ERROR) success = false;
        if (DetourAttach(&(PVOID&)original_GetFileAttributesExA, Hooked_GetFileAttributesExA) != NO_ERROR) success = false;
        if (DetourAttach(&(PVOID&)original_GetFileAttributesExW, Hooked_GetFileAttributesExW) != NO_ERROR) success = false;
        if (DetourAttach(&(PVOID&)original_GetFileAttributesA, Hooked_GetFileAttributesA) != NO_ERROR) success = false;
        if (DetourAttach(&(PVOID&)original_GetFileAttributesW, Hooked_GetFileAttributesW) != NO_ERROR) success = false;

        if (original_PathFileExistsA) {
            DetourAttach(&(PVOID&)original_PathFileExistsA, Hooked_PathFileExistsA);
        }
        if (original_PathFileExistsW) {
            DetourAttach(&(PVOID&)original_PathFileExistsW, Hooked_PathFileExistsW);
        }

        if (original_fopen) {
            DetourAttach(&(PVOID&)original_fopen, Hooked_fopen);
        }

        if (!success) {
            DetourTransactionAbort();
            return false;
        }

        LONG result = DetourTransactionCommit();
        if (result != NO_ERROR) {
            return false;
        }

        if (g_logger) {
            g_logger->log_startup_message();
        }

        ScanGameFiles();

        return true;
    }

    bool uninstall_hooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (original_CreateFileA) DetourDetach(&(PVOID&)original_CreateFileA, Hooked_CreateFileA);
        if (original_CreateFileW) DetourDetach(&(PVOID&)original_CreateFileW, Hooked_CreateFileW);
        if (original_GetFileAttributesExA) DetourDetach(&(PVOID&)original_GetFileAttributesExA, Hooked_GetFileAttributesExA);
        if (original_GetFileAttributesExW) DetourDetach(&(PVOID&)original_GetFileAttributesExW, Hooked_GetFileAttributesExW);
        if (original_GetFileAttributesA) DetourDetach(&(PVOID&)original_GetFileAttributesA, Hooked_GetFileAttributesA);
        if (original_GetFileAttributesW) DetourDetach(&(PVOID&)original_GetFileAttributesW, Hooked_GetFileAttributesW);
        if (original_PathFileExistsA) DetourDetach(&(PVOID&)original_PathFileExistsA, Hooked_PathFileExistsA);
        if (original_PathFileExistsW) DetourDetach(&(PVOID&)original_PathFileExistsW, Hooked_PathFileExistsW);
        if (original_fopen) DetourDetach(&(PVOID&)original_fopen, Hooked_fopen);

        LONG result = DetourTransactionCommit();
        return result == NO_ERROR;
    }
};

int FileSystemHook::total_file_checks = 0;
int FileSystemHook::hidden_file_count = 0;
FileSystemHook::FileEntry FileSystemHook::file_cache[2000] = {};
int FileSystemHook::cache_size = 0;
FileSystemHook::LogThrottle FileSystemHook::log_cache[100] = {};
int FileSystemHook::log_count = 0;
const char* FileSystemHook::CONFIG_FILE_NAME = "hiddenFiles.cfg";

extern "C" {
    __declspec(dllexport) bool __cdecl InstallReCheckerBypass() {
        if (!g_fs_hook) {
            g_fs_hook = new FileSystemHook();
            if (!g_fs_hook->initialize()) {
                delete g_fs_hook;
                g_fs_hook = nullptr;
                return false;
            }
        }
        return g_fs_hook->install_hooks();
    }

    __declspec(dllexport) bool __cdecl UninstallReCheckerBypass() {
        if (g_fs_hook) {
            bool result = g_fs_hook->uninstall_hooks();
            delete g_fs_hook;
            g_fs_hook = nullptr;
            return result;
        }
        return false;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            Sleep(2000);

            g_logger = new EngineLogger();
            InstallReCheckerBypass();

            return 0;
            }, nullptr, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        UninstallReCheckerBypass();
        if (g_logger) {
            delete g_logger;
            g_logger = nullptr;
        }
        break;
    }
    return TRUE;
}