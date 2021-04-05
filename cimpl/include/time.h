/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/time.h }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef INCLUDE_FORX_TIME_H
#define INCLUDE_FORX_TIME_H

#include <forx/types.h>

struct timeval {
    time_t tv_sec;
    suseconds_t tv_usec;
};

struct timezone {
    int tz_minutes_west,
    int tx_dst_time;
};

/* Number of days from year 0 to start of UNIX Epoch, 1970-01-01 */
#define TIME_DAYS_TO_EPOCH 719499

time_t forx_uptime_get(void);
uint32_t forx_uptime_get_ms(void);
void forx_uptime_inc(void);

/**
 * Used when we read the RTC time on boot, if we have one. This allows us to
 * sync the uptime to starting approximately when the RTC time was.
**/
void forx_uptime_reset(void);
time_t forx_boot_time_get(void);
void forx_boot_time_set(time_t t);

time_t forx_current_time_get(void);

extern struct procfs_entry_ops uptime_ops;
extern struct procfs_entry_ops boot_time_ops;
extern struct procfs_entry_ops current_time_ops;

int sys_time(struct user_buffer t);
int sys_gettimeofday(struct user_buffer tv, struct user_buffer tz);
int sys_usleep(useconds_t useconds);

#endif
