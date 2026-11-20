/** Independent stable C API mouse-encoder continuation probe for #26 [13][40]. */
#include <ghostty/vt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern size_t infraternal_vt_snapshot(GhosttyTerminal, unsigned char *, size_t, size_t);
extern size_t infraternal_vt_compare(GhosttyTerminal, GhosttyTerminal, bool);
static size_t encode(GhosttyTerminal t, uint8_t *out, bool motion) {
 GhosttyMouseEncoder encoder; GhosttyMouseEvent event;
 if(ghostty_mouse_encoder_new(NULL,&encoder) || ghostty_mouse_event_new(NULL,&event)) exit(3);
 if(ghostty_mouse_encoder_set_from_terminal(encoder,t)!=GHOSTTY_SUCCESS) exit(3);
 GhosttyMouseEncoderSize size={.size=sizeof(GhosttyMouseEncoderSize),.screen_width=800,.screen_height=480,.cell_width=10,.cell_height=20};
 if(ghostty_mouse_encoder_set(encoder,GHOSTTY_MOUSE_ENCODER_OPT_SIZE,&size)!=GHOSTTY_SUCCESS) exit(3);
 ghostty_mouse_event_set_action(event,motion?GHOSTTY_MOUSE_ACTION_MOTION:GHOSTTY_MOUSE_ACTION_PRESS);
 ghostty_mouse_event_set_button(event,GHOSTTY_MOUSE_BUTTON_LEFT);
 ghostty_mouse_event_set_position(event,(GhosttyMousePosition){.x=20,.y=10});
 size_t len=0; int rc=ghostty_mouse_encoder_encode(encoder,event,out,128,&len);
 ghostty_mouse_event_free(event);ghostty_mouse_encoder_free(encoder);
 if(rc)exit(4);return len;
}
int main(void) {
 const char *inputs[]={"\033c\033[?1000hX","\033c\033[?1003h\033[?1006hX","\033c\033[?1003h\033[?1000hX"};
 unsigned char *paint=malloc(1024*1024);int failures=0;
 for(size_t i=0;i<3;i++){
  GhosttyTerminal a,b;size_t max_scrollback=17*1024*1024;
  if(ghostty_terminal_new(NULL,&a,80,24)!=GHOSTTY_SUCCESS||ghostty_terminal_new(NULL,&b,80,24)!=GHOSTTY_SUCCESS)return 2;
  if(ghostty_terminal_set(a,GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_BYTES,&max_scrollback)!=GHOSTTY_SUCCESS||
     ghostty_terminal_set(b,GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_BYTES,&max_scrollback)!=GHOSTTY_SUCCESS)return 2;
  ghostty_terminal_vt_write(a,(const unsigned char *)inputs[i],strlen(inputs[i]));
  size_t n=infraternal_vt_snapshot(a,paint,1024*1024,256);
  if(!n||n==SIZE_MAX)return 5;
  ghostty_terminal_vt_write(b,paint,n);
  size_t difference=infraternal_vt_compare(a,b,true);
  uint8_t aa[128],bb[128];size_t na=encode(a,aa,i==2),nb=encode(b,bb,i==2);
  bool equal=na==nb&&memcmp(aa,bb,na)==0;
  printf("mouse case=%zu strict_difference=%zu original_report_bytes=%zu replay_report_bytes=%zu equal=%d\n",i,difference,na,nb,equal);
  failures+=!equal;
  ghostty_terminal_free(a);ghostty_terminal_free(b);
 }
 free(paint);return failures?1:0;
}
