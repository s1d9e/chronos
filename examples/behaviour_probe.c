/* behaviour_probe.c — a benign, compilable Linux sample that exercises the
 * behaviors Chronos looks for. Used ONLY for testing the sandbox pipeline
 * against a real traced process. It does nothing harmful:
 *   - creates + writes + deletes a file in /tmp
 *   - checks /proc/self/status for a tracer (anti-debug style)
 *   - maps RWX memory and hides it with PROT_NONE (sleep-obf style)
 *   - opens an outbound socket (connect will fail, that is fine)
 *   - forks a child
 *
 * Build:  gcc -O0 -o probe behaviour_probe.c
 * Run:    chronos run -- ./probe
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

int check_tracer(void) {
    char buf[512];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0)
        return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    return strstr(buf, "TracerPid:") != NULL;
}

int main(void) {
    /* 1. file drop then delete */
    int fd = open("/tmp/ct_drop", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, "payload material\n", 17);
        close(fd);
        unlink("/tmp/ct_drop");
    }

    /* 2. anti-debug style probe */
    check_tracer();

    /* 3. RWX allocation then PROT_NONE (sleep-obfuscation-like cycle) */
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        mprotect(p, 4096, PROT_NONE);
        usleep(50000);
        mprotect(p, 4096, PROT_READ | PROT_EXEC);
        munmap(p, 4096);
    }

    /* 4. outbound connect (to a non-routable addr, will fail) */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) {
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(4444);
        dst.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
        connect(s, (struct sockaddr *)&dst, sizeof(dst));
        close(s);
    }

    /* 5. fork a child that sleeps */
    pid_t c = fork();
    if (c == 0) {
        usleep(100000);
        _exit(0);
    }
    waitpid(c, NULL, 0);

    return 0;
}
