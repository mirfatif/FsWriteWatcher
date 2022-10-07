// https://www.man7.org/linux/man-pages/man7/fanotify.7.html#EXAMPLES
// https://github.com/baskiton/pyfanotify/blob/main/src/ext.c
// https://github.com/inotify-tools/inotify-tools/blob/master/src/inotifywatch.c

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/fanotify.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

//////////////////////////////////////////////////////////////////////////////

#define TAG "notify_fs"

static int print_error(bool with_code, char *format, va_list args)
{
    fprintf(stderr, "%s: ", TAG);
    vfprintf(stderr, format, args);

    if (with_code)
        fprintf(stderr, ": %s", strerror(errno));

    fprintf(stderr, "\n");
    fflush(stderr);
    return EXIT_FAILURE;
}

static int print_err(char *format, ...)
{
    va_list args;
    va_start(args, format);
    print_error(false, format, args);
    va_end(args);
    return EXIT_FAILURE;
}

static int print_err_code(char *format, ...)
{
    va_list args;
    va_start(args, format);
    print_error(true, format, args);
    va_end(args);
    return EXIT_FAILURE;
}

static void print_out(char *format, ...)
{
    printf("%s: ", TAG);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
    fflush(stdout);
}

//////////////////////////////////////////////////////////////////////////////

#define CMD_MAX_LENGTH 256

struct pid_info
{
    char p_cmd[CMD_MAX_LENGTH];
    int uid, gid;
};

static bool get_cmd(pid_t pid, char *buf)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *file = fopen(path, "r");
    if (!file)
        return false;

    char *line = NULL;
    size_t n = 0;

    int len = getline(&line, &n, file);

    if (len > 0)
    {
        if (len > CMD_MAX_LENGTH - 1)
        {
            // print_err("Truncating cmd to %d size", CMD_MAX_LENGTH);
            len = CMD_MAX_LENGTH;
            line[CMD_MAX_LENGTH - 1] = '\0';
            line[CMD_MAX_LENGTH - 2] = line[CMD_MAX_LENGTH - 3] = line[CMD_MAX_LENGTH - 4] = '.';
        }

        for (int i = 0; i < len - 1; i++)
        {
            if (line[i] == '\0')
                line[i] = ' ';
        }

        strcpy(buf, line);
    }

    free(line);
    fclose(file);

    return len > 0;
}

static int get_uid_gid(char *st_line)
{
    char *c = strchr(st_line, '\t');
    if (c)
        return strtol(strchr(c + 1, '\t'), NULL, 10);
    else
        return -1;
}

static void get_pid_info(pid_t pid, struct pid_info *pid_info)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);

    FILE *file = fopen(path, "r");
    if (!file)
        return;

    char *line = NULL;
    size_t n = 0, len;
    int ppid, uid, gid = -1;

    while (getline(&line, &n, file) > 0)
    {
        if (!strncmp(line, "PPid:", 5))
            ppid = strtol(line + 6, NULL, 10);
        else if (!strncmp(line, "Uid:", 4))
            uid = get_uid_gid(line);
        else if (!strncmp(line, "Gid:", 4))
        {
            gid = get_uid_gid(line);
            break;
        }
    }

    free(line);
    fclose(file);

    pid_info->uid = uid;
    pid_info->gid = gid;

    if (ppid <= 0 || !get_cmd(ppid, pid_info->p_cmd))
        pid_info->p_cmd[0] = '\0';
}

struct fs_event
{
    int uid;
    int gid;
    char *cmd;
    char *p_cmd;
    char *evt;
    char *path;
};

static void handle_event(pid_t pid, char *evt, char *path, char *file, bool is_dir, void (*cb)(struct fs_event))
{
    char cmd[CMD_MAX_LENGTH];
    char file_path[PATH_MAX];

    if (!get_cmd(pid, cmd))
        cmd[0] = '\0';

    struct pid_info pi = {.uid = -1, .gid = -1, .p_cmd[0] = '\0'};
    get_pid_info(pid, &pi);

    snprintf(file_path, sizeof(file_path), "%s%s%s%s", path, file ? "/" : "", file ? file : "", is_dir ? "/" : "");
    struct fs_event e = {.uid = pi.uid, .gid = pi.gid, .cmd = cmd, .p_cmd = pi.p_cmd, .evt = evt, .path = file_path};
    cb(e);
}

//////////////////////////////////////////////////////////////////////////////

static int EVENTS[] = {FAN_CREATE, FAN_MODIFY, FAN_ATTRIB, FAN_MOVED_FROM, FAN_MOVED_TO, FAN_DELETE};
static char *EVENT_NAMES[] = {"CREATE", "MODIFY", "ATTRIB", "MOVED_FROM", "MOVED_TO", "DELETE"};

/*
 * We have already received DFID event for MODIFY and
 * ATTRIB (except for ATTRIB when file is deleted).
 */
#define IS_DUP_EVENT(evt) (evt == FAN_MODIFY || evt == FAN_ATTRIB)

static int handle_events(int fan_fd, int mnt_fd, void (*cb)(struct fs_event))
{
    ssize_t info_len;
    struct fanotify_event_metadata *emd;
    struct fanotify_event_info_fid *fid;
    struct file_handle *fh;

    char buf[2048];
    ssize_t buf_len;

    int ev_fd;
    char fd_path[PATH_MAX];
    char file_path[PATH_MAX];
    ssize_t path_len;

    char *file_name;
    int is_dfid, is_dir;

    int err = 0;

    for (;;)
    {
        buf_len = read(fan_fd, buf, sizeof(buf));
        // FAN_NONBLOCK makes read() non-blocking, returns EAGAIN.
        if (buf_len == -1 && errno != EAGAIN)
            return print_err_code("Failed to read fanotify events");

        // EOF or EAGAIN.
        if (buf_len <= 0)
            break;

        // Loop over all events in the buffer.
        for (emd = (struct fanotify_event_metadata *)buf; FAN_EVENT_OK(emd, buf_len); emd = FAN_EVENT_NEXT(emd, buf_len))
        {
            // Check that run-time and compile-time structures match.
            if (emd->vers != FANOTIFY_METADATA_VERSION)
                return print_err("Mismatch of fanotify metadata version");

            if (emd->event_len > FAN_EVENT_METADATA_LEN)
            {
                fid = (struct fanotify_event_info_fid *)(emd + 1);
                is_dir = emd->mask & FAN_ONDIR;
                info_len = emd->event_len - emd->metadata_len;

                while (info_len > 0)
                {
                    if (fid->hdr.info_type != FAN_EVENT_INFO_TYPE_FID && fid->hdr.info_type != FAN_EVENT_INFO_TYPE_DFID_NAME)
                    {
                        err = print_err("Unexpected event type: %d", fid->hdr.info_type);
                        break;
                    }

                    is_dfid = fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME;
                    fh = (struct file_handle *)fid->handle;

                    file_name = is_dfid ? (char *)(fh->f_handle + fh->handle_bytes) : NULL;

                    for (int i = 0; i < 2; i++)
                    {
                        if ((ev_fd = open_by_handle_at(mnt_fd, fh, O_RDONLY)) == -1 && errno == ENOMEM)
                            usleep(100 * 1000);
                        else
                            break;
                    }

                    if (ev_fd == -1)
                    {
                        if (errno != ESTALE)
                        {
                            print_err_code("Failed to open file handle");

                            if (errno == ENOMEM)
                                snprintf(file_path, sizeof(file_path), "(%s)", strerror(errno));
                            else
                            {
                                err = EXIT_FAILURE;
                                break;
                            }
                        }
                        else
                            strcpy(file_path, "(DELETED)");
                    }
                    else
                    {
                        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", ev_fd);
                        path_len = readlink(fd_path, file_path, sizeof(file_path) - 1);

                        close(ev_fd);

                        if (path_len == -1)
                        {
                            err = print_err_code("Failed to read file path");
                            break;
                        }
                        else
                        {
                            file_path[path_len] = '\0';

                            if (!strlen(file_path))
                            {
                                err = print_err_code("Failed to read file path");
                                break;
                            }
                        }
                    }

                    for (int i = 0; i < sizeof(EVENTS) / sizeof(EVENTS[0]); i++)
                    {
                        if ((is_dfid || !IS_DUP_EVENT(EVENTS[i])) && emd->mask & EVENTS[i])
                            handle_event(emd->pid, EVENT_NAMES[i], file_path, file_name, is_dir, cb);
                    }

                    info_len -= fid->hdr.len;
                    fid = (struct fanotify_event_info_fid *)((uint8_t *)fid + fid->hdr.len);
                }

                if (!err && info_len)
                    err = print_err("Failed to read all headers, remaining length: %ld", info_len);
            }
            else
                err = print_err("No (D)FID info received in event");

            close(emd->fd);

            if (err)
                break;
        }

        if (err)
            break;
    }

    return err;
}

//////////////////////////////////////////////////////////////////////////////

static volatile bool terminate = false;

static void stop_fs_events()
{
    terminate = true;
}

static int start_fs_events(void (*cb)(struct fs_event))
{
    int mnt_fd = open("/", O_DIRECTORY | O_RDONLY);
    if (mnt_fd == -1)
        return print_err_code("Failed to open mount FD");

    // FAN_NONBLOCK makes read() non-blocking.
    unsigned int class = FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DFID_NAME | FAN_NONBLOCK;
    int fan_fd = fanotify_init(class, O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1)
    {
        close(mnt_fd);
        return print_err_code("Failed to init fanotify");
    }

    int res = EXIT_SUCCESS;

    unsigned int action = FAN_MARK_ADD | FAN_MARK_FILESYSTEM;
    uint64_t events = FAN_MODIFY | FAN_ATTRIB | FAN_CREATE | FAN_DELETE | FAN_MOVE | FAN_ONDIR;

    if (fanotify_mark(fan_fd, action, events, AT_FDCWD, "/"))
        res = print_err_code("Failed to add fanotify mark");
    else
    {
        print_out("Listening to filesystem events...");

        struct pollfd pfd = {.fd = fan_fd, .events = POLLIN};
        int rc;

        while (!terminate)
        {
            rc = poll(&pfd, 1, 500);

            if (rc == 0)
                // 500ms timed out
                continue;

            if (rc == -1)
            {
                if (errno != EINTR)
                    res = print_err_code("Filesystem notify poll failed");

                break;
            }

            if (pfd.revents & POLLERR || pfd.revents & POLLNVAL)
            {
                res = print_err("Netlink poll failed");
                break;
            }

            // Should not happen.
            if (!(pfd.revents & POLLIN))
                continue;

            // Do not receive event if stopped.
            if (terminate)
                break;

            if (res = handle_events(fan_fd, mnt_fd, cb))
                break;

            // EOF
            if (pfd.revents & POLLHUP)
                break;
        }
    }

    close(fan_fd);
    close(mnt_fd);

    return res;
}

static void print_event(struct fs_event evt)
{
    printf("%d.%d [%s] [%s] %s %s\n", evt.uid, evt.gid, evt.cmd, evt.p_cmd, evt.evt, evt.path);
    fflush(NULL);
}

int main()
{
    return start_fs_events(&print_event);
}
