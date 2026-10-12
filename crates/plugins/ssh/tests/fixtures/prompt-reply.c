/* A tiny real ELF/socket peer keeps prompt admission tests independent of Rust debug-section size. */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(void) {
    const char *path = getenv("INFRATERNAL_PROMPT_FIXTURE");
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (!path || strlen(path) >= sizeof address.sun_path) return 1;
    strcpy(address.sun_path, path);
    int stream = socket(AF_UNIX, SOCK_STREAM, 0);
    if (stream < 0 || connect(stream, (struct sockaddr *)&address, sizeof address)) return 1;
    char reply[32];
    size_t length = 0;
    ssize_t count;
    while ((count = read(stream, reply + length, sizeof reply - length)) > 0) {
        length += (size_t)count;
        if (length == sizeof reply) return 1;
    }
    close(stream);
    return count < 0 || length != sizeof "synthetic-reply" - 1 ||
        memcmp(reply, "synthetic-reply", length);
}
