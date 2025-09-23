#ifndef MONITOR_H_INCLUDED
#define MONITOR_H_INCLUDED

#define MON_EXIT_RESTART       64          /* Exit code which instructs the monitor to restart the child   */
#define MON_EXIT_ORPHAN        65          /* Exit normally, but instead of killing children, orphan them  */

#define MON_CHECKIN(id)        mon_checkin((id), __FILE__, __LINE__)

/** monitor counter IDs */
enum mon_cnt_id
{
    MON_MAIN_LOOP,
    MON_XMPP_LOOP,
    MON_LAST,
};

extern void mon_start(int argc, char *argv[]);
extern void mon_checkin(enum mon_cnt_id id, char *file, int line);
extern void mon_stackdump(void);
extern void mon_process_terminate(pid_t child);

#endif /* MONITOR_H_INCLUDED */
