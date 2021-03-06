#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...)    fprintf(stdout, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)    /* Don't do anything in release builds */
#endif

#endif /*__DEBUG_H__*/
