//
// Created by lleaves on 2024/1/18.
//

#include <jni.h>
#include <elf.h>
#include <android/log.h>
#include <sys/ptrace.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <linux/uio.h>
#include <stdio.h>
#include <string.h>
#include <asm-generic/fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>

#define log(...) __android_log_print(ANDROID_LOG_DEBUG, "native", __VA_ARGS__)

void install_seccomp_filter();
static void read_file(pid_t child, char *file, user_regs_struct regs);
JNIEXPORT void start_trace();
void process_signal(int pid);

/*
作者说:
这种方案在可执行文件下，是可行的，能够跑的通。
但是在app环境下，ptrace将不再适用，容易触发各种异常信号，
并且在ptrace环境下容易被各大厂商app的安全模块检测出来
 */

JNIEXPORT void start_trace()
{
    int status;

    // fork
    pid_t pid = fork();

    log("fork pid : %d", pid);
    if (pid == 0)
    {
        //子进程

        pid = getppid();
        log("parent pid : %d", pid);
        int state = ptrace(PTRACE_ATTACH, pid, 0, 0);
        if(state == -1)
        {
            log("PTRACE_ATTACH failed");
        }
        const unsigned long default_ptrace_options = (
            PTRACE_O_TRACESYSGOOD |
            PTRACE_O_TRACEFORK |
            PTRACE_O_TRACEVFORK |
            PTRACE_O_TRACEVFORKDONE |
            PTRACE_O_TRACECLONE |
            PTRACE_O_TRACEEXEC |
            PTRACE_O_TRACEEXIT );
        state = ptrace(PTRACE_SETOPTIONS, pid, 0, default_ptrace_options | PTRACE_O_TRACESECCOMP);
        if(state == -1){
            log("PTRACE_SETOPTIONS failed");
        }
        waitpid(pid, &status, 0);
        // if status is SIGSTOP
        if ( WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
        {
            process_signal(pid);
        }
    }
    else
    {
        //父亲进程,被调试的对象,啥也不干,就死循环处理消息
        install_seccomp_filter();//父进程安装过滤规则?
        kill(getpid(), SIGSTOP);//tracee停止
        kill(getpid(), SIGCONT);//tracee继续运行? 这里需要被tracer触发执行
        log("waitpid");
        //然后父进程返回,继续运行正常app进程
    }

}

static void read_file(pid_t child, char *file, user_regs_struct regs)
{
    char *child_addr;
    int i;
    child_addr = (char *) regs.regs[1];
    do {
        long val;
        char *p;
        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1) {
            log("PTRACE_PEEKTEXT error: %s", strerror(errno));
            exit(1);
        }
        child_addr += sizeof (long);
        p = (char *) &val;
        for (i = 0; i < sizeof (long); ++i, ++file) {
            *file = *p++;
            if (*file == '\0') break;
        }
    } while (i == sizeof (long));
}

/* 监听并读取打开的文件名?*/
void process_signal(int pid)
{
    int status;
    while(1) 
    {
        char filename[255] = {0};
        struct user_regs_struct regs;
        struct iovec io;
        io.iov_base = &regs;
        io.iov_len = sizeof(regs);

        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);
//        log("waitpid status : %x", status);

        ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);

        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) )
        {
//            log("seccomp event %d", regs.regs[8]);
            switch (regs.regs[8])
            {
                case __NR_openat:
                    read_file(pid, filename, regs);
                    log("[Openat called], filename : %s \n", filename);
                    break;
                case __NR_read:
                    log("[Read called] , fd : %d\n", regs.regs[0]);
                    break;
                case __NR_close:
                    log("[Close called] , fd : %d\n", regs.regs[0]);
                    break;

            }
        }

        if (WIFEXITED(status)){
            break;
        }
    }
}

// 对__NR_openat,__NR_read,__NR_close 跟踪, 其它调用允许放行
void install_seccomp_filter()
{
    struct sock_filter filter[] = 
    {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        log("prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        log("when setting seccomp filter");
    }
}