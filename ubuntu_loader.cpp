
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

static const char *DEFAULT_ROOTFS = "未定";

static const char *MOUNT_DEV = "dev";
static const char *MOUNT_PROC = "proc";
static const char *MOUNT_SYS = "sys";
static const char *MOUNT_DEVPTS = "devpts";

static volatile sig_atomic_t caught_signal = 0;
static pid_t child_pid = -1;

struct MountState {
    bool dev;
    bool proc;
    bool sys;
    bool devpts;
};

static MountState mounts = {false, false, false, false};

static void signal_handler(int sig) {
    caught_signal = sig;
    if (child_pid > 0) {
        kill(child_pid, sig);
    }
}

static void print_error(const char *operation, const char *path) {
    fprintf(stderr, "[ubuntu-loader] %s: %s: %s\n",
            operation, path, strerror(errno));
}

static bool is_directory(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool path_join(char *output, size_t size,
                      const char *root, const char *name) {
    int result = snprintf(output, size, "%s/%s", root, name);
    return result > 0 && static_cast<size_t>(result) < size;
}

static bool check_directory(const char *root, const char *name) {
    char path[PATH_MAX];

    if (!path_join(path, sizeof(path), root, name)) {
        fprintf(stderr, "[ubuntu-loader] Path too long\n");
        return false;
    }

    if (!is_directory(path)) {
        fprintf(stderr,
                "[ubuntu-loader] Missing directory: %s\n",
                path);
        return false;
    }

    return true;
}

static bool check_rootfs(const char *root) {
    struct stat st;

    if (stat(root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr,
                "[ubuntu-loader] Invalid RootFS: %s\n",
                root);
        return false;
    }

    if (!check_directory(root, "bin") ||
        !check_directory(root, "dev") ||
        !check_directory(root, "proc") ||
        !check_directory(root, "sys") ||
        !check_directory(root, "dev/pts")) {
        return false;
    }

    char bash_path[PATH_MAX];
    char sh_path[PATH_MAX];

    if (!path_join(bash_path, sizeof(bash_path),
                   root, "bin/bash")) {
        return false;
    }

    if (!path_join(sh_path, sizeof(sh_path),
                   root, "bin/sh")) {
        return false;
    }

    if (access(bash_path, X_OK) != 0 &&
        access(sh_path, X_OK) != 0) {
        fprintf(stderr,
                "[ubuntu-loader] No executable shell found\n");
        return false;
    }

    return true;
}

static bool mount_filesystems(const char *root) {
    char dev[PATH_MAX];
    char proc[PATH_MAX];
    char sys[PATH_MAX];
    char devpts[PATH_MAX];

    if (!path_join(dev, sizeof(dev), root, "dev") ||
        !path_join(proc, sizeof(proc), root, "proc") ||
        !path_join(sys, sizeof(sys), root, "sys") ||
        !path_join(devpts, sizeof(devpts), root, "dev/pts")) {
        return false;
    }

    if (mount("/dev", dev, NULL, MS_BIND, NULL) != 0) {
        print_error("mount /dev", dev);
        return false;
    }
    mounts.dev = true;

    if (mount("proc", proc, "proc",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) {
        print_error("mount proc", proc);
        return false;
    }
    mounts.proc = true;

    if (mount("sysfs", sys, "sysfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) {
        print_error("mount sysfs", sys);
        return false;
    }
    mounts.sys = true;

    if (mount("devpts", devpts, "devpts",
              MS_NOSUID | MS_NOEXEC,
              "mode=0620,ptmxmode=0666") != 0) {
        print_error("mount devpts", devpts);
        return false;
    }
    mounts.devpts = true;

    return true;
}

static bool unmount_one(const char *root,
                        const char *name,
                        bool *mounted) {
    if (!*mounted) {
        return true;
    }

    char path[PATH_MAX];

    if (!path_join(path, sizeof(path), root, name)) {
        return false;
    }

    if (umount2(path, 0) != 0) {
        print_error("umount", path);
        return false;
    }

    *mounted = false;
    return true;
}

static bool cleanup_mounts(const char *root) {
    bool result = true;

    if (!unmount_one(root, MOUNT_DEVPTS, &mounts.devpts)) {
        result = false;
    }

    if (!unmount_one(root, MOUNT_SYS, &mounts.sys)) {
        result = false;
    }

    if (!unmount_one(root, MOUNT_PROC, &mounts.proc)) {
        result = false;
    }

    if (!unmount_one(root, MOUNT_DEV, &mounts.dev)) {
        result = false;
    }

    return result;
}

static void child_exec(const char *root,
                       int argc,
                       char **argv,
                       int command_index) {
    if (chdir(root) != 0) {
        print_error("chdir", root);
        _exit(126);
    }

    if (chroot(".") != 0) {
        print_error("chroot", root);
        _exit(126);
    }

    if (chdir("/") != 0) {
        print_error("chdir", "/");
        _exit(126);
    }

    setenv("HOME", "/root", 1);
    setenv("USER", "root", 1);
    setenv("LOGNAME", "root", 1);
    setenv("SHELL", "/bin/bash", 1);
    setenv("PATH",
           "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           1);
    setenv("TERM", "xterm-256color", 0);

    if (command_index < argc) {
        execvp(argv[command_index], &argv[command_index]);
        fprintf(stderr,
                "[ubuntu-loader] Cannot execute %s: %s\n",
                argv[command_index], strerror(errno));
        _exit(127);
    }

    char *bash_args[] = {
        const_cast<char *>("/bin/bash"),
        const_cast<char *>("-l"),
        NULL
    };

    execv("/bin/bash", bash_args);

    char *sh_args[] = {
        const_cast<char *>("/bin/sh"),
        const_cast<char *>("-l"),
        NULL
    };

    execv("/bin/sh", sh_args);

    fprintf(stderr,
            "[ubuntu-loader] Unable to start shell: %s\n",
            strerror(errno));

    _exit(127);
}

static int run_ubuntu(const char *root,
                      int argc,
                      char **argv,
                      int command_index) {
    if (!check_rootfs(root)) {
        return 1;
    }

    printf("[ubuntu-loader] RootFS: %s\n", root);

    if (!mount_filesystems(root)) {
        cleanup_mounts(root);
        return 1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);

    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    child_pid = fork();

    if (child_pid < 0) {
        print_error("fork", "ubuntu");
        cleanup_mounts(root);
        return 1;
    }

    if (child_pid == 0) {
        child_exec(root, argc, argv, command_index);
        _exit(126);
    }

    printf("[ubuntu-loader] Ubuntu started\n");
    printf("[ubuntu-loader] Type exit to return to TWRP\n");

    int status = 0;
    pid_t result;

    do {
        result = waitpid(child_pid, &status, 0);
    } while (result < 0 && errno == EINTR);

    child_pid = -1;

    if (result < 0) {
        print_error("waitpid", "ubuntu");
        cleanup_mounts(root);
        return 1;
    }

    bool cleanup_ok = cleanup_mounts(root);

    printf("[ubuntu-loader] Ubuntu stopped\n");

    if (!cleanup_ok) {
        fprintf(stderr,
                "[ubuntu-loader] WARNING: Mount cleanup incomplete\n");
        fprintf(stderr,
                "[ubuntu-loader] A reboot may be required to clear stale mounts\n");
        return 1;
    }

    if (caught_signal != 0) {
        return 128 + caught_signal;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return 1;
}

static void show_help(const char *program) {
    printf("Ubuntu ARM64 Recovery Loader\n\n");
    printf("Usage:\n");
    printf("  %s [rootfs] [command] [arguments...]\n", program);
    printf("\n");
    printf("Examples:\n");
    printf("  %s\n", program);
    printf("  %s /data/ubuntu\n", program);
    printf("  %s /data/ubuntu /bin/bash\n", program);
    printf("  %s /data/ubuntu /usr/bin/uname -a\n", program);
    printf("\n");
    printf("Default RootFS: %s\n", DEFAULT_ROOTFS);
}

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fprintf(stderr,
                "[ubuntu-loader] Root privileges are required\n");
        return 1;
    }

    if (argc > 1 &&
        (strcmp(argv[1], "--help") == 0 ||
         strcmp(argv[1], "-h") == 0)) {
        show_help(argv[0]);
        return 0;
    }

    const char *root = DEFAULT_ROOTFS;
    int command_index = argc;

    if (argc > 1 && argv[1][0] != '-') {
        root = argv[1];
        command_index = 2;
    }

    printf("[ubuntu-loader] ARM64 Recovery Loader\n");

    return run_ubuntu(root, argc, argv, command_index);
}
