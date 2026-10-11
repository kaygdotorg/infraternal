/* Declares the versioned ELF capability note, retained even in stripped builds (#154, D217).
 * This is a compatibility marker, not a release signature or authentication proof. */
SECTIONS {
  .note.infraternal (TYPE = SHT_NOTE) : ALIGN(4) {
    LONG(12) LONG(4) LONG(0x49464341)
    BYTE(73) BYTE(78) BYTE(70) BYTE(82) BYTE(65) BYTE(84)
    BYTE(69) BYTE(82) BYTE(78) BYTE(65) BYTE(76) BYTE(0)
    LONG(1)
  }
}
INSERT BEFORE .text;
