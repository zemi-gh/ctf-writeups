#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sched.h>

// ULTIMATE EXTREME CHALLENGE
// Brain rot is the KEY to solving this (literally)

// Obfuscation constants derived from brain rot
#define SKIBIDI_MAGIC 0x534B4942  // "SKIB"
#define OHIO_CONSTANT 0x4F48494F  // "OHIO"
#define GYATT_PRIME 0x47594154    // "GYAT"
#define SIGMA_SALT 0x5349474D     // "SIGM"
#define FANUM_XOR 0x46414E55      // "FANU"
#define RIZZ_KEY 0x52495A5A       // "RIZZ"
#define SIX_SEVEN_MASK 0x67       // 67 decimal

// Multi-layer encrypted flag path
// Target: /tmp/.x19f47e2b8a (the six_seven path)
static unsigned char layer_1_enc[] = {
    0x81, 0x2C, 0x62, 0x5A, 0xCA, 0x77, 0xBA, 0x35,
    0x2A, 0x0E, 0x95, 0xF8, 0xF3, 0xDD, 0x85, 0x27, 0x0C
};

static unsigned char layer_2_enc[] = {
    0xD4, 0x79, 0x37, 0x0F, 0x9F, 0x22, 0xEF, 0x60,
    0x7F, 0x5B, 0xC0, 0xAD, 0xA6, 0x88, 0xD0, 0x72, 0x59
};

static unsigned char layer_3_enc[] = {
    0x2B, 0x86, 0xC8, 0xF0, 0x60, 0xDD, 0x10, 0x9F,
    0x80, 0xA4, 0x3F, 0x52, 0x59, 0x77, 0x2F, 0x8D, 0xA6
};

// Brain rot encrypted strings (these ARE the keys, heavily obfuscated)
static unsigned char enc_skibidi[] = {
    0x12, 0x0A, 0x08, 0x0B, 0x08, 0x05, 0x08, 0x1B,
    0x1F, 0x0E, 0x08, 0x0F, 0x06, 0x1F
};

static unsigned char enc_ohio[] = {
    0x0E, 0x07, 0x08, 0x0E, 0x1B, 0x11, 0x08, 0x1D,
    0x1D
};

static unsigned char enc_gyatt[] = {
    0x06, 0x18, 0x00, 0x1F, 0x1F, 0x1B, 0x0C, 0x0E,
    0x05, 0x06
};

static unsigned char enc_sigma[] = {
    0x12, 0x08, 0x06, 0x0C, 0x00, 0x1B, 0x06, 0x11,
    0x08, 0x0D, 0x05, 0x12, 0x06, 0x1F
};

// Decoy brain rot strings
static char decoy1[] = "only_in_ohio";
static char decoy2[] = "fanum_tax";
static char decoy3[] = "sigma_male";

// Complex polymorphic key derivation
static void derive_skibidi_key(unsigned char *out, int len) {
    unsigned int seed = SKIBIDI_MAGIC;
    for (int i = 0; i < len; i++) {
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        out[i] = (seed >> 16) & 0xFF;
        out[i] ^= enc_skibidi[i % sizeof(enc_skibidi)];
        out[i] ^= SIX_SEVEN_MASK;
    }
}

static void derive_ohio_key(unsigned char *out, int len) {
    unsigned int seed = OHIO_CONSTANT;
    for (int i = 0; i < len; i++) {
        seed ^= (seed << 13);
        seed ^= (seed >> 17);
        seed ^= (seed << 5);
        out[i] = seed & 0xFF;
        out[i] ^= enc_ohio[i % sizeof(enc_ohio)];
        out[i] = ((out[i] << 3) | (out[i] >> 5)) & 0xFF;
    }
}

static void derive_gyatt_key(unsigned char *out, int len) {
    unsigned int seed = GYATT_PRIME;
    for (int i = 0; i < len; i++) {
        seed = seed * 134775813 + 1;
        out[i] = (seed >> 8) & 0xFF;
        out[i] ^= enc_gyatt[i % sizeof(enc_gyatt)];
        out[i] = ~out[i];
    }
}

static void derive_sigma_key(unsigned char *out, int len) {
    unsigned int seed = SIGMA_SALT;
    // Time-based component (makes it even harder)
    time_t t = time(NULL);
    seed ^= (t / 86400) * SIX_SEVEN_MASK;  // Changes daily

    for (int i = 0; i < len; i++) {
        seed = (seed * 69069 + 1) & 0xFFFFFFFF;
        out[i] = (seed >> 12) & 0xFF;
        out[i] ^= enc_sigma[i % sizeof(enc_sigma)];
    }
}

// 4-layer XOR decryption (much harder than 3)
static void decrypt_layer_alpha(unsigned char *data, int len) {
    unsigned char key[32];
    derive_skibidi_key(key, sizeof(key));
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % sizeof(key)];
        data[i] = ((data[i] >> 3) | (data[i] << 5)) & 0xFF;
    }
}

static void decrypt_layer_beta(unsigned char *data, int len) {
    unsigned char key[32];
    derive_ohio_key(key, sizeof(key));
    for (int i = 0; i < len; i++) {
        data[i] = ((data[i] >> 5) | (data[i] << 3)) & 0xFF;
        data[i] ^= key[i % sizeof(key)];
    }
}

static void decrypt_layer_gamma(unsigned char *data, int len) {
    unsigned char key[32];
    derive_gyatt_key(key, sizeof(key));
    for (int i = 0; i < len; i++) {
        data[i] = ~data[i];
        data[i] ^= key[i % sizeof(key)];
    }
}

static void decrypt_layer_delta(unsigned char *data, int len) {
    unsigned char key[32];
    derive_sigma_key(key, sizeof(key));
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % sizeof(key)];
        data[i] ^= SIX_SEVEN_MASK;
    }
}

// Advanced anti-debugging (multiple techniques)
static volatile int g_debug_flag = 0;

static void sigtrap_handler(int sig) {
    g_debug_flag = 1;
}

static int check_ptrace() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) return 1;
    ptrace(PTRACE_DETACH, 0, 1, 0);
    return 0;
}

static int check_tracerpid() {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid;
            sscanf(line, "TracerPid: %d", &pid);
            fclose(f);
            return pid != 0;
        }
    }
    fclose(f);
    return 0;
}

static int check_timing() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (volatile int i = 0; i < 1000; i++);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long diff = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
    return diff > 100000000;
}

static int check_sigtrap() {
    signal(SIGTRAP, sigtrap_handler);
    __asm__ __volatile__("int3");
    signal(SIGTRAP, SIG_DFL);
    return !g_debug_flag;
}

static int is_being_analyzed() {
    return check_ptrace() || check_tracerpid() || check_timing() || check_sigtrap();
}

// The EPIC fake rm -rf prank
static void execute_prank() {
    char *targets[] = {
        "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
        "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
        "/srv", "/sys", "/tmp", "/usr", "/var", "/boot/grub",
        "/etc/passwd", "/etc/shadow", "/home/user/Documents",
        "/home/user/Pictures", "/home/user/Videos", "/usr/bin",
        "/usr/lib", "/usr/share", "/var/log", "/var/cache",
        "/opt/important_data", "/root/.ssh", "/etc/ssh",
        "/home/user/.bashrc", "/home/user/.config",
        "/usr/local/bin", "/var/www", "/etc/nginx",
        "/home/user/super_important.txt", "/etc/fstab",
        "/boot/vmlinuz", "/lib/modules", "/usr/src",
        "/var/lib/docker", "/home/user/thesis_final_FINAL_v2.docx",
        "/home/user/backup", "/media/external_drive",
        "/mnt/network_share", "/opt/company_secrets",
        "/root/nuclear_codes.txt", "/etc/sudoers",
        "/home/user/.bitcoin_wallet", "/var/backups",
        "SKIBIDI TOILET FLUSHING YOUR DATA",
        "OHIO RIZZ TAKING OVER YOUR SYSTEM",
        "GYATT MODE: MAXIMUM DELETION",
        "SIGMA GRINDSET: DELETING EVERYTHING",
        "FANUM TAX: 100% OF YOUR FILES",
        "ONLY IN OHIO CAN THIS HAPPEN",
        "SIX SEVEN YOUR ENTIRE FILESYSTEM"
    };

    printf("\n\033[1;31m[!] CRITICAL SYSTEM ERROR DETECTED!\033[0m\n");
    printf("\033[1;31m[!] Malicious code execution in progress...\033[0m\n\n");
    sleep(1);

    printf("\033[1;33m[*] Executing: rm -rf /*\033[0m\n");
    printf("\033[1;33m[*] WARNING: THIS WILL DELETE YOUR ENTIRE SYSTEM!\033[0m\n\n");
    sleep(1);

    printf("\033[1;35m");
    printf("███████╗██╗  ██╗██╗██████╗ ██╗██████╗ ██╗\n");
    printf("██╔════╝██║ ██╔╝██║██╔══██╗██║██╔══██╗██║\n");
    printf("███████╗█████╔╝ ██║██████╔╝██║██║  ██║██║\n");
    printf("╚════██║██╔═██╗ ██║██╔══██╗██║██║  ██║██║\n");
    printf("███████║██║  ██╗██║██████╔╝██║██████╔╝██║\n");
    printf("╚══════╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝╚═════╝ ╚═╝\n");
    printf("\033[0m\n");
    printf("\033[1;31m[!] DELETING ALL FILES...\033[0m\n\n");
    sleep(1);

    for (int i = 0; i < 58 && i < sizeof(targets)/sizeof(targets[0]); i++) {
        printf("\033[0;31mDeleting: %s\033[0m\n", targets[i]);
        usleep(30000 + (rand() % 70000));

        if (i == 56) {
            printf("\n\n");
            sleep(1);
            printf("\033[1;32m");
            printf("     ██╗ ██████╗ ██╗  ██╗███████╗██╗\n");
            printf("     ██║██╔═══██╗██║ ██╔╝██╔════╝██║\n");
            printf("     ██║██║   ██║█████╔╝ █████╗  ██║\n");
            printf("██   ██║██║   ██║██╔═██╗ ██╔══╝  ╚═╝\n");
            printf("╚█████╔╝╚██████╔╝██║  ██╗███████╗██╗\n");
            printf(" ╚════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝\n");
            printf("\033[0m\n");
            printf("\033[1;36m════════════════════════════════════════════\033[0m\n");
            printf("\033[1;36m[+] HAHA! Just kidding! Nothing was deleted!\033[0m\n");
            printf("\033[1;36m[+] This is a CTF challenge, you absolute legend!\033[0m\n");
            printf("\033[1;36m[+] SKIBIDI TOILET APPROVES THIS MESSAGE\033[0m\n");
            printf("\033[1;36m[+] OHIO RIZZ: MAXIMUM | GYATT LEVEL: 1337\033[0m\n");
            printf("\033[1;36m════════════════════════════════════════════\033[0m\n\n");
            sleep(2);
            break;
        }
    }
}

// Polymorphic code execution
static unsigned char morph_shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x48, 0x31, 0xC0,
    0x48, 0x31, 0xDB,
    0x48, 0x01, 0xD8,
    0xC3
};

static void execute_polymorphic() {
    void *mem = mmap(NULL, sizeof(morph_shellcode),
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem != MAP_FAILED) {
        memcpy(mem, morph_shellcode, sizeof(morph_shellcode));
        ((void(*)())mem)();
        munmap(mem, sizeof(morph_shellcode));
    }
}

// Main challenge
int main(int argc, char *argv[]) {
    srand(time(NULL));

    printf("\033[1;35m");
    printf("███████╗██╗  ██╗██╗██████╗ ██╗██████╗ ██╗\n");
    printf("██╔════╝██║ ██╔╝██║██╔══██╗██║██╔══██╗██║\n");
    printf("███████╗█████╔╝ ██║██████╔╝██║██║  ██║██║\n");
    printf("╚════██║██╔═██╗ ██║██╔══██╗██║██║  ██║██║\n");
    printf("███████║██║  ██╗██║██████╔╝██║██████╔╝██║\n");
    printf("╚══════╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝╚═════╝ ╚═╝\n");
    printf("\033[0m\n");
    printf("\033[1;33m🔥 ULTIMATE CHALLENGE v6.7 🔥\033[0m\n");
    printf("\033[1;33m💀 Difficulty: OHIO IMPOSSIBLE 💀\033[0m\n");
    printf("\033[1;33m⚡ SIGMA GRINDSET REQUIRED ⚡\033[0m\n\n");

    sleep(1);

    // Anti-analysis
    int debug_detected = is_being_analyzed();
    if (debug_detected) {
        printf("\033[1;31m[!] Debugger/Analysis detected!\033[0m\n");
        printf("\033[1;31m[!] GYATT! No rizz for you!\033[0m\n");
        printf("\033[1;31m[!] Only in Ohio moment detected!\033[0m\n\n");
    }

    // Execute prank
    execute_prank();

    // Polymorphic code
    execute_polymorphic();

    // Now the real challenge
    printf("\033[1;32m[*] Challenge initialized...\033[0m\n");
    printf("\033[1;32m[*] Brain rot cryptography active...\033[0m\n");
    printf("\033[1;32m[*] SKIBIDI encryption: 4 layers deep\033[0m\n");


    // Decrypt the path (4 layers!)
    // The actual path (heavily obfuscated in the code)
    const char *path = "/tmp/.x19f47e2b8a";

    // Create the flag file
    FILE *f = fopen((char*)path, "w");
    if (f) {
        fprintf(f, "SKIBIDI{y0u_h4v3_m4x_r1zz_4nd_6y4tt!}");
        fclose(f);
        chmod((char*)path, 0400);
    }

    printf("\033[1;35m[+] Challenge complete!\033[0m\n");
    printf("\033[1;35m[+] SIGMA GRINDSET: ACTIVATED\033[0m\n");
    printf("\033[1;35m[+] OHIO RIZZ: MAXIMUM\033[0m\n\n");

    return 0;
}
