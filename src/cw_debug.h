#ifndef __CW_DEBUG_H__
#define __CW_DEBUG_H__

#define CW_DEBUG

#ifdef CW_DEBUG

#define cw_log(msg, args...) do { \
    printf(msg, ##args);  \
  } while (0);

#else

#define cw_log(msg, args...)

#endif

#endif
