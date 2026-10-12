/** Common VT device-query output for live and replay terminal regression specs. */
export const QUERY_OUTPUT = [
  "\u001b[c",                   // DA1
  "\u001b[>c",                  // DA2
  "\u001b[=c",                  // DA3
  "\u001b[5n",                  // DSR operating status
  "\u001b[6n",                  // DSR cursor position
  "\u001b]11;?\u0007",          // OSC background color
  "\u001b[>q",                  // XTVERSION
  "\u001b[?u",                  // extended keyboard protocol query
  "\u001b[?2004$p",             // DECRQM
  "\u001b]10;?\u0007",          // OSC foreground color
  "\u001b]12;?\u0007",          // OSC cursor color
  "\u001b]4;0;?\u0007",         // OSC palette color
  "\u001b]4;15;?\u0007",        // OSC palette color at a second index
  "\u001bP$qm\u001b\\",        // DECRQSS rendition
  "\u001bP+q544e;436f\u001b\\", // XTGETTCAP terminal name and colors
  "\u001b[14t",                 // window pixel dimensions
  "\u001b[16t",                 // cell pixel dimensions
  "\u001b[18t",                 // window cell dimensions
].join("");
