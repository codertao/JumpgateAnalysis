/*
 * Message-layer recording + MitM shim for Jumpgate's Msb32.dll.
 *
 * It sits INSIDE the crypto boundary: the RakNet AES transport and the
 * per-message salt/running-sum obfuscation are both outside these hook points,
 * so here every game message is plaintext and can be read or rewritten in
 * both directions. No network crypto is reimplemented.
 *
 * Install: rename the stock Msb32.dll to Msb32_orig.dll, drop this in as
 *          Msb32.dll. All four exports forward to the original.
 *
 * Recording: appends every message to jgcap.bin next to the exe:
 *   u8 dir(0=S>C,1=C>S)  u32 ms(GetTickCount)  u16 len  u8 data[len]
 * (data[0] = game message type). Read it with jgcap_dump.py / jgdecode.py.
 * The login password is redacted in the recorded copy (redact_login); older
 * captures made before this change still contain it.
 *
 * MitM rules (optional): jgmitm_rules.txt next to the exe, one per line.
 *   # comment
 *   drop S <type>              drop an incoming message (retyped to an
 *                              unused id so the dispatcher ignores it)
 *   set  S <type> <off> <byte> patch one byte of an incoming message
 *   set  C <type> <off> <byte> patch one byte of an outgoing message
 *   <type>/<byte> are hex (09 or 0x09), <off> decimal. Offsets are into the
 *   decoded message, byte 0 = type. Rules apply to the matching type only.
 *   'drop C' is not offered here: the encoder hook cannot cleanly suppress a
 *   send (see notes) -- use 'set' to neutralize an outgoing message instead.
 *
 * All rules are logged to jgmitm.log so an edited session is auditable.
 */
#include <windows.h>
#include <stdio.h>

#define DROP_RETYPE 0xFF        /* unused game type -> dispatcher default/ignore */
#define MAXRULES 256

static HMODULE g_orig;
static FARPROC p_GetIP, p_Login, p_Tick, p_catchPacket;
static CRITICAL_SECTION g_lock;
static FILE *g_log, *g_evt;

struct rule { unsigned char dir, type, drop; int off; unsigned char val; };
static struct rule g_rules[MAXRULES];
static int g_nrules;

/* Login (C>S type 0x05, short; the 176-byte 0x05 state report is not touched):
 *   [05] callsign\0 password\0 ... version @0x16
 * Only the RECORDED copy is changed: everything after the callsign's NUL up to
 * the version field is zeroed and the password slot reads "*". The game still
 * sends the real message. */
#define LOGIN_MAX_LEN 64
#define LOGIN_VERSION_OFF 0x16
static const unsigned char *redact_login(const unsigned char *data, int len,
                                         unsigned char *buf)
{
    if (len < 2 || len > LOGIN_MAX_LEN || data[0] != 0x05) return data;
    memcpy(buf, data, len);
    int p = 1;
    while (p < len && buf[p]) p++;               /* end of callsign */
    p++;                                          /* start of password */
    int end = len < LOGIN_VERSION_OFF ? len : LOGIN_VERSION_OFF;
    if (p < end) {
        memset(buf + p, 0, end - p);
        buf[p] = '*';
    }
    return buf;
}

static void log_msg(unsigned char dir, const unsigned char *data, int len)
{
    if (!g_log || len <= 0 || len > 0xffff) return;
    unsigned char red[LOGIN_MAX_LEN];
    if (dir == 1) data = redact_login(data, len, red);
    unsigned int ms = GetTickCount();
    unsigned short l = (unsigned short)len;
    EnterCriticalSection(&g_lock);
    fwrite(&dir,1,1,g_log); fwrite(&ms,4,1,g_log);
    fwrite(&l,2,1,g_log);   fwrite(data,1,len,g_log);
    fflush(g_log);
    LeaveCriticalSection(&g_lock);
}

static void evt(const char *fmt, ...)
{
    if (!g_evt) return;
    va_list ap; va_start(ap, fmt);
    EnterCriticalSection(&g_lock);
    vfprintf(g_evt, fmt, ap); fputc('\n', g_evt); fflush(g_evt);
    LeaveCriticalSection(&g_lock);
    va_end(ap);
}

/* returns 1 if the message was dropped (caller should neutralize it) */
static int apply_rules(unsigned char dir, unsigned char *msg, int len)
{
    if (len < 1) return 0;
    for (int i = 0; i < g_nrules; i++) {
        struct rule *r = &g_rules[i];
        if (r->dir != dir || r->type != msg[0]) continue;
        if (r->drop) {
            evt("drop %c type=0x%02x len=%d", dir ? 'C' : 'S', msg[0], len);
            return 1;
        }
        if (r->off >= 0 && r->off < len) {
            evt("set  %c type=0x%02x off=%d %02x->%02x",
                dir ? 'C' : 'S', msg[0], r->off, msg[r->off], r->val);
            msg[r->off] = r->val;
        }
    }
    return 0;
}

/* ---- forwarded exports ---- */
__attribute__((naked)) void GetIP(void) { __asm__("jmp *%0" :: "m"(p_GetIP)); }
__attribute__((naked)) void Login(void) { __asm__("jmp *%0" :: "m"(p_Login)); }
__attribute__((naked)) void Tick(void)  { __asm__("jmp *%0" :: "m"(p_Tick)); }

/* catchPacket(src=encoded, dst=decoded game buffer, len); decoded len = len-1 */
typedef char (__cdecl *catch_fn)(const unsigned char *src, unsigned char *dst, int len);
char __cdecl catchPacket(const unsigned char *src, unsigned char *dst, int len)
{
    char r = ((catch_fn)p_catchPacket)(src, dst, len);
    int dl = len - 1;
    if (dl > 0) {
        if (apply_rules(0, dst, dl))
            dst[0] = DROP_RETYPE;          /* make the dispatcher ignore it */
        log_msg(0, dst, dl);               /* log post-edit (what the game sees) */
    }
    return r;
}

/* ---- send-side detour on the encoder 0x9c8ca0: void enc(src, dst, len) ---- */
#define ENC_ADDR 0x009c8ca0u
static const unsigned char enc_prologue[6] = {0x83,0xec,0x08,0x53,0x56,0x57};
static unsigned char *g_tramp;
typedef void (__cdecl *enc_fn)(const unsigned char *src, unsigned char *dst, int len);

static void __cdecl enc_hook(const unsigned char *src, unsigned char *dst, int len)
{
    if (len > 0 && len <= 4096 && g_nrules) {
        unsigned char tmp[4096];
        memcpy(tmp, src, len);
        apply_rules(1, tmp, len);          /* 'set' only on send; drop N/A */
        log_msg(1, tmp, len);
        ((enc_fn)g_tramp)(tmp, dst, len);
        return;
    }
    log_msg(1, src, len);
    ((enc_fn)g_tramp)(src, dst, len);
}

static void install_send_hook(void)
{
    unsigned char *t = (unsigned char *)ENC_ADDR;
    if (memcmp(t, enc_prologue, sizeof enc_prologue) != 0) {
        evt("send hook: prologue mismatch, not installed (different build?)");
        return;
    }
    g_tramp = VirtualAlloc(NULL, 16, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_tramp) return;
    memcpy(g_tramp, enc_prologue, 6);
    g_tramp[6] = 0xe9;
    *(int *)(g_tramp + 7) = (int)((t + 6) - (g_tramp + 11));
    DWORD old;
    if (!VirtualProtect(t, 6, PAGE_EXECUTE_READWRITE, &old)) return;
    t[0] = 0xe9; *(int *)(t + 1) = (int)((unsigned char *)enc_hook - (t + 5)); t[5] = 0x90;
    VirtualProtect(t, 6, old, &old);
    FlushInstructionCache(GetCurrentProcess(), t, 6);
    evt("send hook installed at 0x%08x", ENC_ADDR);
}

static int hx(const char *s){ return (int)strtol(s, NULL, 16); }

static void load_rules(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (g_nrules < MAXRULES && fgets(line, sizeof line, f)) {
        char op[16], d[8], ty[16], v[16]; int off;
        if (line[0] == '#' || line[0] == '\n') continue;
        int n = sscanf(line, "%15s %7s %15s %d %15s", op, d, ty, &off, v);
        struct rule r = {0};
        r.dir = (d[0]=='C'||d[0]=='c') ? 1 : 0;
        r.type = (unsigned char)hx(ty);
        if (n >= 3 && strcmp(op,"drop")==0 && r.dir==0) { r.drop=1; r.off=-1; }
        else if (n == 5 && strcmp(op,"set")==0) { r.off=off; r.val=(unsigned char)hx(v); }
        else continue;
        g_rules[g_nrules++] = r;
    }
    fclose(f);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_lock);
        char path[MAX_PATH]; GetModuleFileNameA(inst, path, MAX_PATH);
        char *slash = strrchr(path, '\\'); if (slash) slash[1]=0; else path[0]=0;
        char orig[MAX_PATH], logp[MAX_PATH], rulp[MAX_PATH], evtp[MAX_PATH];
        snprintf(orig,sizeof orig,"%sMsb32_orig.dll",path);
        snprintf(logp,sizeof logp,"%sjgcap.bin",path);
        snprintf(rulp,sizeof rulp,"%sjgmitm_rules.txt",path);
        snprintf(evtp,sizeof evtp,"%sjgmitm.log",path);
        g_orig = LoadLibraryA(orig);
        if (!g_orig) return FALSE;
        p_GetIP=GetProcAddress(g_orig,"GetIP"); p_Login=GetProcAddress(g_orig,"Login");
        p_Tick=GetProcAddress(g_orig,"Tick");  p_catchPacket=GetProcAddress(g_orig,"catchPacket");
        if (!p_GetIP||!p_Login||!p_Tick||!p_catchPacket) return FALSE;
        g_log = fopen(logp, "ab");
        g_evt = fopen(evtp, "a");
        load_rules(rulp);
        evt("--- attach: %d rule(s) loaded ---", g_nrules);
        install_send_hook();
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_log) fclose(g_log);
        if (g_evt) fclose(g_evt);
    }
    return TRUE;
}
