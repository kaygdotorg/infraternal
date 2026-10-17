/** Emits a real pinned-engine repaint for the add-host output witness regression (#189). */
#include <ghostty/vt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern size_t infraternal_vt_snapshot(GhosttyTerminal, unsigned char *, size_t, size_t);

int main(void) {
    GhosttyTerminal terminal;
    GhosttyTerminalOptions options = {.cols = 80, .rows = 24, .max_scrollback = 0};
    if (ghostty_terminal_new(NULL, &terminal, options)) return 2;
    const char *output = "\033cBEFORE_HANDOVER\r\nAFTER_HANDOVER\r\n";
    ghostty_terminal_vt_write(terminal, (const unsigned char *)output, strlen(output));
    unsigned char *snapshot = malloc(1048576);
    if (!snapshot) return 3;
    size_t length = infraternal_vt_snapshot(terminal, snapshot, 1048576, 0);
    if (!length || length == SIZE_MAX || length > 1048576) return 4;
    int failed = fwrite(snapshot, 1, length, stdout) != length;
    free(snapshot);
    ghostty_terminal_free(terminal);
    return failed;
}
