#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#ifndef __GNUC__
#pragma comment(lib, "ws2_32.lib")
#endif

#define MAX_CONCURRENT_CLIENTS 64
#define DEFAULT_RL_MAX_REQ     20
#define DEFAULT_RL_WINDOW_MS   10000
#define LOG_FILE_PATH          "trustgate_system.log"

#define IPWL_MAX_ENTRIES 1024
#define IPWL_IP_LEN      16
#define RATELIMIT_MAX_TRACKED 4096

typedef enum {
    LOG_INFO,
    LOG_WARN,
    LOG_ALLOW,
    LOG_BLOCK,
    LOG_ERROR
} log_level_t;

static FILE *g_log_file = NULL;
static CRITICAL_SECTION g_log_lock;
static int g_log_initialized = 0;

static void get_timestamp(char *buf, size_t size) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, size, "%02d/%02d/%04d %02d:%02d:%02d",
             st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
}

static const char *level_tag(log_level_t level) {
    switch (level) {
        case LOG_INFO:  return "SYSTEM";
        case LOG_WARN:  return "WARNING";
        case LOG_ALLOW: return "ACCESS_OK";
        case LOG_BLOCK: return "BLOCKED";
        case LOG_ERROR: return "ERROR";
        default:        return "UNKNOWN";
    }
}

static const char *level_color(log_level_t level) {
    switch (level) {
        case LOG_ALLOW: return "\033[92m";
        case LOG_BLOCK: return "\033[91m";
        case LOG_WARN:  return "\033[93m";
        case LOG_ERROR: return "\033[91m";
        default:        return "\033[96m";
    }
}

static int logger_init(const char *filepath) {
    InitializeCriticalSection(&g_log_lock);
    g_log_file = fopen(filepath, "a");
    if (!g_log_file) return 0;
    g_log_initialized = 1;
    return 1;
}

static void logger_write(log_level_t level, const char *ip, const char *fmt, ...) {
    if (!g_log_initialized) return;

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    char message[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    EnterCriticalSection(&g_log_lock);

    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%-9s] [Client: %s] %s\n",
                timestamp, level_tag(level), ip ? ip : "N/A", message);
        fflush(g_log_file);
    }

    printf("%s[%s] [%-9s] [Peer: %s] %s\033[0m\n",
           level_color(level), timestamp, level_tag(level), ip ? ip : "N/A", message);

    LeaveCriticalSection(&g_log_lock);
}

static void logger_shutdown(void) {
    if (!g_log_initialized) return;
    EnterCriticalSection(&g_log_lock);
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    LeaveCriticalSection(&g_log_lock);
    DeleteCriticalSection(&g_log_lock);
    g_log_initialized = 0;
}

static char g_ips[IPWL_MAX_ENTRIES][IPWL_IP_LEN];
static int  g_ip_count = 0;

static int compare_ip(const void *a, const void *b) {
    struct in_addr addr_a, addr_b;
    inet_pton(AF_INET, (const char *)a, &addr_a);
    inet_pton(AF_INET, (const char *)b, &addr_b);
    uint32_t va = ntohl(addr_a.s_addr);
    uint32_t vb = ntohl(addr_b.s_addr);
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

static int is_valid_ipv4(const char *ip_str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_str, &(sa.sin_addr)) == 1;
}

static void ipwl_add_ip(const char *ip_str) {
    if (g_ip_count < IPWL_MAX_ENTRIES && is_valid_ipv4(ip_str)) {
        strncpy(g_ips[g_ip_count], ip_str, IPWL_IP_LEN - 1);
        g_ips[g_ip_count][IPWL_IP_LEN - 1] = '\0';
        g_ip_count++;
    }
}

static int ipwl_is_trusted(const char *ip) {
    if (g_ip_count == 0) return 0;

    struct in_addr target;
    if (inet_pton(AF_INET, ip, &target) != 1) return 0;
    uint32_t target_val = ntohl(target.s_addr);

    int lo = 0, hi = g_ip_count - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        struct in_addr mid_addr;
        inet_pton(AF_INET, g_ips[mid], &mid_addr);
        uint32_t mid_val = ntohl(mid_addr.s_addr);

        if (mid_val == target_val) return 1;
        if (mid_val < target_val) lo = mid + 1;
        else hi = mid - 1;
    }
    return 0;
}

typedef struct {
    char ip[16];
    int  hits;
    DWORD window_start_ms;
    int  in_use;
} rl_entry_t;

static rl_entry_t g_rl_table[RATELIMIT_MAX_TRACKED];
static CRITICAL_SECTION g_rl_lock;
static int g_rl_max_requests = DEFAULT_RL_MAX_REQ;
static int g_rl_window_ms = DEFAULT_RL_WINDOW_MS;
static int g_rl_initialized = 0;

static unsigned int hash_ip(const char *ip) {
    unsigned int h = 5381;
    for (const char *p = ip; *p; p++) {
        h = ((h << 5) + h) + (unsigned char)(*p);
    }
    return h % RATELIMIT_MAX_TRACKED;
}

static void ratelimit_init(int max_requests, int window_ms) {
    memset(g_rl_table, 0, sizeof(g_rl_table));
    InitializeCriticalSection(&g_rl_lock);
    g_rl_max_requests = max_requests;
    g_rl_window_ms = window_ms;
    g_rl_initialized = 1;
}

static int ratelimit_allow(const char *ip) {
    if (!g_rl_initialized) return 1;

    int allowed = 1;
    DWORD now = GetTickCount();

    EnterCriticalSection(&g_rl_lock);

    unsigned int idx = hash_ip(ip);
    unsigned int start = idx;
    rl_entry_t *slot = NULL;

    do {
        rl_entry_t *e = &g_rl_table[idx];
        if (e->in_use && strncmp(e->ip, ip, sizeof(e->ip)) == 0) {
            slot = e;
            break;
        }
        if (!e->in_use && slot == NULL) {
            slot = e;
        }
        idx = (idx + 1) % RATELIMIT_MAX_TRACKED;
    } while (idx != start);

    if (slot == NULL) {
        LeaveCriticalSection(&g_rl_lock);
        return 1;
    }

    if (!slot->in_use) {
        strncpy(slot->ip, ip, sizeof(slot->ip) - 1);
        slot->ip[sizeof(slot->ip) - 1] = '\0';
        slot->in_use = 1;
        slot->hits = 0;
        slot->window_start_ms = now;
    }

    if (now - slot->window_start_ms >= (DWORD)g_rl_window_ms) {
        slot->window_start_ms = now;
        slot->hits = 0;
    }

    slot->hits++;
    if (slot->hits > g_rl_max_requests) {
        allowed = 0;
    }

    LeaveCriticalSection(&g_rl_lock);
    return allowed;
}

static void ratelimit_shutdown(void) {
    if (!g_rl_initialized) return;
    DeleteCriticalSection(&g_rl_lock);
    g_rl_initialized = 0;
}

static volatile LONG g_shutdown_requested = 0;
static SOCKET g_server_sock = INVALID_SOCKET;
static HANDLE g_client_slots_sem = NULL;

typedef struct {
    SOCKET sock;
    char   ip[INET_ADDRSTRLEN];
} client_ctx_t;

static BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        logger_write(LOG_INFO, "NT-SYSTEM", "Service termination requested. Stopping components...");
        InterlockedExchange(&g_shutdown_requested, 1);
        if (g_server_sock != INVALID_SOCKET) {
            closesocket(g_server_sock);
        }
        return TRUE;
    }
    return FALSE;
}

// مراقبة الضغط على Ctrl + S لإيقاف البرنامج
DWORD WINAPI keyboard_listener(LPVOID param) {
    INPUT_RECORD ir[128];
    DWORD read;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

    while (!g_shutdown_requested) {
        if (ReadConsoleInputA(hStdin, ir, 128, &read)) {
            for (DWORD i = 0; i < read; i++) {
                if (ir[i].EventType == KEY_EVENT && ir[i].Event.KeyEvent.bKeyDown) {
                    if ((ir[i].Event.KeyEvent.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) &&
                        ir[i].Event.KeyEvent.wVirtualKeyCode == 'S') {

                        printf("\n\033[91m[!] Ctrl+S detected. Shutting down TrustGate daemon...\033[0m\n");
                        InterlockedExchange(&g_shutdown_requested, 1);
                        if (g_server_sock != INVALID_SOCKET) {
                            closesocket(g_server_sock);
                        }
                        return 0;
                    }
                }
            }
        }
    }
    return 0;
}

static void send_response(SOCKET sock, int allowed) {
    static const char *ok =
        "HTTP/1.1 200 OK\r\nServer: Windows-HTTP-Services/5.1\r\nContent-Type: text/plain\r\nContent-Length: 22\r\n\r\nTrustGate: Access OK\r\n";
    static const char *denied =
        "HTTP/1.1 403 Forbidden\r\nServer: Windows-HTTP-Services/5.1\r\nContent-Type: text/plain\r\nContent-Length: 15\r\n\r\nAccess Denied!\r\n";

    const char *resp = allowed ? ok : denied;
    send(sock, resp, (int)strlen(resp), 0);
}

static DWORD WINAPI client_worker(LPVOID param) {
    client_ctx_t *ctx = (client_ctx_t *)param;

    if (!ratelimit_allow(ctx->ip)) {
        logger_write(LOG_WARN, ctx->ip, "Rate threshold exceeded. Connection dropped.");
        closesocket(ctx->sock);
        free(ctx);
        ReleaseSemaphore(g_client_slots_sem, 1, NULL);
        return 0;
    }

    if (ipwl_is_trusted(ctx->ip)) {
        logger_write(LOG_ALLOW, ctx->ip, "Source IP verified on whitelist. Access granted.");
        send_response(ctx->sock, 1);
    } else {
        logger_write(LOG_BLOCK, ctx->ip, "Unauthorized connection attempt blocked.");
        send_response(ctx->sock, 0);
    }

    closesocket(ctx->sock);
    free(ctx);
    ReleaseSemaphore(g_client_slots_sem, 1, NULL);
    return 0;
}

static SOCKET create_listening_socket(int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((u_short)port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

static void print_banner(void) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    SetConsoleTitleA("Windows NT Security - TrustGate Service [Active]");

    printf("\033[96m");
    printf("Microsoft Windows [Version 10.0.26100.560]\n");
    printf("(c) Microsoft Corporation. All rights reserved.\n\n");
    printf("\033[1;34m");
    printf("========================================================\n");
    printf("  [NT-CORE] TrustGate Network Filtering Daemon v4.2     \n");
    printf("  [STATUS]  Protected Subsystem Initialized Successfully\n");
    printf("  [INFO]    Press [Ctrl + S] to terminate service safely\n");
    printf("========================================================\n");
    printf("\033[0m");
}

int main(int argc, char *argv[]) {
    int port = 8080;

    if (!logger_init(LOG_FILE_PATH)) return 1;

    print_banner();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        logger_shutdown();
        return 1;
    }

    char input_ip[32];
    printf("\n\033[93m[CONFIG] Enter trusted IPv4 address for filtering rule: \033[0m");
    if (scanf("%31s", input_ip) == 1) {
        if (is_valid_ipv4(input_ip)) {
            ipwl_add_ip(input_ip);
            printf("\033[92m[OK] Rule added successfully for target: %s\033[0m\n", input_ip);
        } else {
            printf("\033[91m[ERROR] Malformed IPv4 structure. Skipping.\033[0m\n");
        }
    }

    if (g_ip_count > 0) {
        qsort(g_ips, g_ip_count, IPWL_IP_LEN, compare_ip);
    }

    printf("\n\033[96m[SYSTEM] Starting network socket listener on port %d...\033[0m\n\n", port);

    ratelimit_init(DEFAULT_RL_MAX_REQ, DEFAULT_RL_WINDOW_MS);

    g_client_slots_sem = CreateSemaphore(NULL, MAX_CONCURRENT_CLIENTS, MAX_CONCURRENT_CLIENTS, NULL);
    if (!g_client_slots_sem) {
        WSACleanup();
        logger_shutdown();
        return 1;
    }

    SetConsoleCtrlHandler(console_handler, TRUE);

    // تشغيل مراقب لوحة المفاتيح للاستماع لاختصار Ctrl + S
    CreateThread(NULL, 0, keyboard_listener, NULL, 0, NULL);

    g_server_sock = create_listening_socket(port);
    if (g_server_sock == INVALID_SOCKET) {
        CloseHandle(g_client_slots_sem);
        WSACleanup();
        logger_shutdown();
        return 1;
    }

    logger_write(LOG_INFO, "NT-SYSTEM", "Service is running and listening on port %d", port);

    while (!g_shutdown_requested) {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);

        SOCKET client_sock = accept(g_server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock == INVALID_SOCKET) {
            if (g_shutdown_requested) break;
            continue;
        }

        WaitForSingleObject(g_client_slots_sem, INFINITE);

        client_ctx_t *ctx = malloc(sizeof(client_ctx_t));
        if (!ctx) {
            closesocket(client_sock);
            ReleaseSemaphore(g_client_slots_sem, 1, NULL);
            continue;
        }
        ctx->sock = client_sock;

        if (inet_ntop(AF_INET, &client_addr.sin_addr, ctx->ip, sizeof(ctx->ip)) == NULL) {
            strcpy(ctx->ip, "127.0.0.1");
        }

        HANDLE h = CreateThread(NULL, 0, client_worker, ctx, 0, NULL);
        if (!h) {
            closesocket(client_sock);
            free(ctx);
            ReleaseSemaphore(g_client_slots_sem, 1, NULL);
        } else {
            CloseHandle(h);
        }
    }

    if (g_server_sock != INVALID_SOCKET) closesocket(g_server_sock);
    CloseHandle(g_client_slots_sem);
    ratelimit_shutdown();
    WSACleanup();
    logger_shutdown();
    return 0;
}
