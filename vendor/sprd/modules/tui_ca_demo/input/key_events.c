/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/poll.h>
#include <linux/input.h>


#define MAX_DEVICES 5
#define EVIOCSSUSPENDBLOCK _IOW('E', 0x91, int)

static struct pollfd ev_fds[MAX_DEVICES];
static unsigned ev_count = 0;


int ev_init(void)
{
    struct dirent* de;
    int fd;
    DIR* dir = opendir("/dev/input");

    if (dir != 0) {
        while ((de = readdir(dir))) {
            if (strncmp(de->d_name, "event", 5)) {
                continue;
            }

            fd = openat(dirfd(dir), de->d_name, O_RDONLY);

            if (fd < 0) {
                continue;
            }

            ev_fds[ev_count].fd = fd;
            ev_fds[ev_count].events = POLLIN;

            ioctl(fd, EVIOCSSUSPENDBLOCK, 1);

            ev_count++;

            if (ev_count == MAX_DEVICES) {
                break;
            }
        }
    }

    closedir(dir);

    return 0;
}

void ev_exit(void)
{
    while (ev_count > 0) {
        close(ev_fds[--ev_count].fd);
    }
}

/* wait: 0 dont wait; -1 wait forever; >0 wait ms */
int ev_get(struct input_event* ev, int wait_ms)
{
    int r;
    unsigned n;

    do {
        r = poll(ev_fds, ev_count, wait_ms);

        if (r > 0) {
            for (n = 0; n < ev_count; n++) {
                if (ev_fds[n].revents & POLLIN) {
                    r = read(ev_fds[n].fd, ev, sizeof(*ev));

                    if (r == sizeof(*ev)) {
                        return 0;
                    }
                }
            }
        }
    }
    while (wait_ms == -1);

    return -1;
}
