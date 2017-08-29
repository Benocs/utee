/*
@(#)File:           debug.h
@(#)Purpose:        Definitions for the debugging system
@(#)Author:         J Leffler
@(#)Copyright:      (C) JLSS 1990-93,1997-99,2003,2005,2008,2011,2013,2016
@(#)Derivation:     debug.h 3.13 2016/01/17 15:47:27
*/

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <time.h>
#include "kludge.h"

/* Control whether debugging macros are active at compile time */
#undef DB_ACTIVE
#ifdef DEBUG
#define DB_ACTIVE 1
#else
#define DB_ACTIVE 0
#endif /* DEBUG */

#define LOG_DEBUG0       0
#define LOG_DEBUG1       1
#define LOG_DEBUG2       2
#define LOG_DEBUG3       3
#define LOG_DEBUG4       4
#define LOG_DEBUG5       5
#define LOG_DEBUG6       6
#define LOG_DEBUG7       7
#define LOG_DEBUG8       8
#define LOG_DEBUG9       9
#define LOG_DEBUG       10
#define LOG_INFO        20
#define LOG_WARN        30
#define LOG_WARNING     LOG_WARN
#define LOG_ERROR       40
#define LOG_CRITICAL    50

#define LOG_ALL         0xFF

#define DB_TRACE_BUF_SIZE 255
#define DB_TRACE_LOGLVL_BUF_SIZE 10

/*
** TRACE is a legacy interface; new code should use DB_TRACE.
**
** Usage:  TRACE((level, fmt, ...));
**
** "level" is the debugging level which must be operational for the output
** to appear. "fmt" is a printf format string. "..." is whatever extra
** arguments fmt requires (possibly nothing).
**
** Usage:  DB_TRACE(level, fmt, ...);
**
** The structure of the macros means that the code is always validated
** but is not called when DEBUG is undefined.
** -- See chapter 8 of 'The Practice of Programming', by Kernighan and Pike.
*/
#define TRACE(x) \
            do { if (DB_ACTIVE) db_print x; } while (0)
#define DB_TRACE(level, ...)                                                \
    do {                                                                    \
        if (DB_ACTIVE) {                                                    \
            char msgbuf[DB_TRACE_BUF_SIZE];                                 \
            char loglvlbuf[DB_TRACE_LOGLVL_BUF_SIZE];                       \
            switch (level) {                                                \
                case LOG_DEBUG:                                             \
                    snprintf(loglvlbuf, sizeof(loglvlbuf), "DEBUG");        \
                    break;                                                  \
                case LOG_INFO:                                              \
                    snprintf(loglvlbuf, sizeof(loglvlbuf), "INFO");         \
                    break;                                                  \
                case LOG_WARN:                                              \
                    snprintf(loglvlbuf, sizeof(loglvlbuf), "WARN");         \
                    break;                                                  \
                case LOG_ERROR:                                             \
                    snprintf(loglvlbuf, sizeof(loglvlbuf), "ERROR");        \
                    break;                                                  \
                case LOG_CRITICAL:                                          \
                    snprintf(loglvlbuf, sizeof(loglvlbuf), "CRITICAL");     \
                    break;                                                  \
                case LOG_ALL:                                               \
                    snprintf(loglvlbuf, sizeof(loglvlbuf), "ALL");          \
                    break;                                                  \
                default:                                                    \
                    snprintf(loglvlbuf, sizeof(loglvlbuf), "%d", level);    \
                    break;                                                  \
            }                                                               \
            snprintf(msgbuf, sizeof(msgbuf), __VA_ARGS__);                  \
            db_print(level, "%lu - %s - %s:%d:%s(): %s\n",                  \
                    time(NULL), loglvlbuf, __FILE__, __LINE__, __func__,    \
                    msgbuf);                                                \
        }                                                                   \
    } while (0)

/*
** Usage:  DB_CALL(level, ...);
**
** Example: DB_CALL(1, dump_structure(db_getfileptr(), "tag", arg1, arg2));
**
** If trace is active at given level, execute the code in the variable
** arguments.  Normally used to selectively execute printing functions.
*/
#define DB_CALL(level, ...)\
            do { if (DB_ACTIVE && db_getdebug() >= (level)) { __VA_ARGS__; } } while (0)

/*
** DB_TRACKING(); uses the FEATURE macro from klduge.h to embed a string
** in a function identifying that the file is compiled with debug
** enabled.  It should be the preferred mechanism for recording this, in
** preference to the non-descriptive, passive jlss_id_debug_enabled
** string (which can't identify the source file by name).  The old
** mechanism will be phased out at some time after 2017-01-01.
*/
#define DB_TRACKING() \
            do { if (DB_ACTIVE) FEATURE("** DEBUG ** (" __FILE__ ")") } while (0)

#ifndef lint
#ifdef DEBUG
/* This string can't be made extern - multiple definition in general */
static const char jlss_id_debug_enabled[] = "@(#)*** DEBUG ***";
#endif /* DEBUG */
#endif /* lint */

extern int      db_getdebug(void);
extern int      db_newindent(void);
extern int      db_oldindent(void);
extern int      db_setdebug(int level);
extern int      db_setindent(int i);
extern void     db_print(int level, const char *fmt,...);
extern void     db_setfilename(const char *fn);
extern void     db_setfileptr(FILE *fp);
extern FILE    *db_getfileptr(void);

/* Semi-private function */
extern const char *db_indent(void);

/**************************************\
** MULTIPLE DEBUGGING SUBSYSTEMS CODE **
\**************************************/

/*
** MDTRACE is a legacy interface; new code should use DB_MDTRACE.
**
** Usage:  MDTRACE((subsys, level, fmt, ...));
**
** "subsys" is the debugging system to which this statement belongs.
** The significance of the subsystems is determined by the programmer,
** except that the functions such as db_print refer to subsystem 0.
** "level" is the debugging level which must be operational for the
** output to appear. "fmt" is a printf format string. "..." is
** whatever extra arguments fmt requires (possibly nothing).
**
** Usage:  DB_MDTRACE(subsys, level, fmt, ...);
*/
#define MDTRACE(x) \
            do { if (DB_ACTIVE) db_mdprint x; } while (0)
#define DB_MDTRACE(subsys, level, ...) \
            do { if (DB_ACTIVE) db_mdprint(subsys, level, __VA_ARGS__); } while (0)

/*
** Usage:  DB_MDCALL(subsys, level, ...);
**
** Example: DB_CALL(subsys, 1, dump_structure(db_getfileptr(), "tag", arg1, arg2));
**
** If trace is active at given level for given subsystem, execute the
** code in the variable arguments.  Normally used to selectively execute
** printing functions.
*/
#define DB_MDCALL(subsys, level, ...) \
            do { if (DB_ACTIVE && db_mdgetdebug(subsys) >= (level)) { __VA_ARGS__; } } while (0)

extern int      db_mdgetdebug(int subsys);
extern int      db_mdparsearg(char *arg);
extern int      db_mdsetdebug(int subsys, int level);
extern void     db_mdprint(int subsys, int level, const char *fmt,...);
extern void     db_mdsubsysnames(char * const *names);

#endif /* DEBUG_H */
