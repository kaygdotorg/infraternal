/* Launch a private probe test with inherited control fd3, then act as its tiny real ELF image. */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "launch")) {
        int source = open("/dev/null", O_RDONLY);
        if (source < 0 || dup2(source, 3) < 0 || fcntl(3, F_SETFD, 0) < 0) return 1;
        if (source != 3) close(source);
        execv(argv[2], argv + 2);
        return 1;
    }
    return fcntl(3, F_GETFD) >= 0;
}
