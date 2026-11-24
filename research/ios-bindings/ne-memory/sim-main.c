/* iOS Simulator entry point for ne-memory: Xcode's clang links this file
 * around the Rust static library, which does all the work (J1158). */
int ne_memory_main(void);

int main(void) { return ne_memory_main(); }
