/** Independent C-ABI allocation-failure probe for resize invariants [40], issue #26. */
#include <ghostty/vt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
struct context {size_t left; int enabled;};
static void *allocate(void *ctx,size_t len,uint8_t alignment,uintptr_t ret){
 (void)ret; struct context *c=ctx;if(c->enabled){if(c->left==0)return NULL;c->left--;}
 void *p=NULL;size_t a=alignment<sizeof(void*)?sizeof(void*):alignment;
 if(posix_memalign(&p,a,len))return NULL;return p;
}
static bool resize_mem(void *c,void *p,size_t old,uint8_t a,size_t n,uintptr_t ret){(void)c;(void)p;(void)old;(void)a;(void)n;(void)ret;return false;}
static void *remap_mem(void *c,void *p,size_t old,uint8_t a,size_t n,uintptr_t ret){(void)c;(void)p;(void)old;(void)a;(void)n;(void)ret;return NULL;}
static void free_mem(void *c,void *p,size_t n,uint8_t a,uintptr_t ret){(void)c;(void)n;(void)a;(void)ret;free(p);}
extern size_t infraternal_vt_snapshot(GhosttyTerminal,uint8_t*,size_t,size_t);
int main(int argc,char **argv){
 struct context ctx={0,0};GhosttyAllocatorVtable v={allocate,resize_mem,remap_mem,free_mem};GhosttyAllocator a={&ctx,&v};
 GhosttyTerminal t=NULL;if(ghostty_terminal_new(&a,&t,80,24)!=GHOSTTY_SUCCESS)return 2;
 size_t max_scrollback=17825792;
 if(ghostty_terminal_set(t,GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_BYTES,&max_scrollback)!=GHOSTTY_SUCCESS)return 2;
 const char *input="\033cPRIMARY\033[?47hALT\033[?47l";ghostty_terminal_vt_write(t,(const uint8_t*)input,strlen(input));
 ctx.enabled=1;ctx.left=argc>1?strtoul(argv[1],NULL,10):0;
 int result=ghostty_terminal_resize(t,20000,2,0,0);ctx.enabled=0;
 uint16_t cols=0,rows=0;ghostty_terminal_get(t,GHOSTTY_TERMINAL_DATA_COLS,&cols);ghostty_terminal_get(t,GHOSTTY_TERMINAL_DATA_ROWS,&rows);
 printf("allocation_step=%s resize_result=%d cols=%u rows=%u\n",argv[1],result,cols,rows);fflush(stdout);
 if(result!=0){uint8_t *buf=malloc(1048576);size_t size=infraternal_vt_snapshot(t,buf,1048576,0);free(buf);printf("snapshot_length=%zu\n",size);}
 ghostty_terminal_free(t);return 0;
}
