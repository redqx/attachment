#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>


#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/user.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/prctl.h>
#include <asm/unistd_64.h>

#define PATH_MAX 128

static void process_signals(pid_t child);
static void read_filename_from_regs(pid_t child, char *file,struct user_regs_struct regs);
void putdata_to_regs(pid_t pid, unsigned long long addr, char *str, long sz);

int main()
{
    pid_t pid;
    int status;
    if ((pid = fork()) == 0) 
    {
        ptrace(PTRACE_TRACEME, 0, 0, 0);

        // === 配置SECCOMP规则
        struct sock_filter filter[] = 
        {
            // 监控__NR_openat
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = 
        {
            .len = (unsigned short)(sizeof(filter) / sizeof (filter[0])),
            .filter = filter,
        };
        
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return 1;
        }
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
            perror("when setting seccomp filter");
            return 1;
        }
        kill(getpid(), SIGSTOP); // 暂停


        ssize_t count;
        char buf[256];
        int fd;

        fd = syscall(__NR_openat,fd,"/home/kali/tmp/flag.txt", O_RDONLY);//syscall 打开

        if (fd == -1) 
        {
            perror("open");
            return 1;
        }
        // read the file and write it to stdout
        while((count = syscall(__NR_read, fd, buf, sizeof(buf))) > 0) //读取文件
        {
            syscall(__NR_write, STDOUT_FILENO, buf, count);//写到STD_OUT
        }
        printf("\n");
        syscall(__NR_close, fd);//关闭局部
    } 
    else 
    {
        waitpid(pid, &status, 0);//接收 kill(getpid(), SIGSTOP); 
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);//设置 ptrace模式
        //我不知道这个有什么用? 后续代码中已经设置了 ptrace(PTRACE_SYSCALL, child, 0, 0);


        process_signals(pid);
        return 0;
    }
}


static void process_signals(pid_t child)
{
    char file_to_redirect[256] = "/home/kali/tmp/hacker";
    char file_to_avoid[256] = "/home/kali/tmp/flag.txt";
    int status;
    while(1) {

        char orig_file[PATH_MAX];
        struct user_regs_struct regs;
        // struct iovec io;
        // io.iov_base = &regs;
        // io.iov_len = sizeof(regs);

        //ptrace(PTRACE_SYSCALL, child, 0, 0);
        ptrace(PTRACE_CONT, child, 0, 0);//好像用PTRACE_SYSCALL和PTRACE_CONT都行

        waitpid(child, &status, 0);
        
        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        // PTRACE_O_TRACESECCOMP (since Linux 3.5)
        // Stop the tracee when a seccomp(2) SECCOMP_RET_TRACE
        // rule is triggered.  A waitpid(2) by the tracer will
        // return a status value such that
        // status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) )//好像这里就决定了下面的信号只能是SECCOMP过滤的
        {

            // raw system call number in orig_rax
            switch (regs.orig_rax)
            {
                case __NR_openat:
                    printf("[Openat %s]\n", (char *)regs.rsi);
                    read_filename_from_regs(child, orig_file, regs);
                    //if (strcmp(file_to_avoid, (char *)regs.rsi) == 0) //??? 还可以读取子进程指针
                    if (strcmp(file_to_avoid, (char *)orig_file) == 0)
                    {
                        // change the filename in the child process
                        putdata_to_regs(child, (unsigned long long)regs.rsi, (char*)file_to_redirect, strlen(file_to_avoid)+1);
                        //重定向,读取另外一个文件
                        //read_filename(child, orig_file, regs);
                        //printf("[Openat changed %s] \n", orig_file);
                    }
                    break;
            }
        }
        //printf("syscall id %d\n",regs.orig_rax);
            
        if (WIFEXITED(status))
        {
            break;
        }
    }
}

//8个8个的读取
static void read_filename_from_regs(pid_t child, char *file,struct user_regs_struct regs)
{
    char *child_addr;
    int i;

    // filename address in rsi
    child_addr = (char *) regs.rsi;
    
    do {
        long val;
        char *p;
        // read the filename in the child process
        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1) {
            fprintf(stderr, "PTRACE_PEEKTEXT error: %s", strerror(errno));
            exit(1);
        }
        child_addr += sizeof (long);
        p = (char *) &val;
        for (i = 0; i < sizeof (long); ++i, ++file) //一次性读取8个字节
        {
            *file = *p++;
            if (*file == '\0') 
            {
                break;
            }
        }
    } while (i == sizeof (long));

    
}



//8个8个的写入
void putdata_to_regs(pid_t pid, unsigned long long  addr, char *str, long sz)
{
    // change the string in the child process
    int i = 0, j = sz / sizeof(long);
    char *s = str;
    long val;

    while (i < j) 
    {
        ptrace(PTRACE_POKEDATA, pid, addr + i * 8, *(long *)(s + i * 8));
        ++ i;
    }
    j = sz % sizeof(long);
    
    // read the last part of the string
    // and merge it with the previous part
    
    val = ptrace(PTRACE_PEEKTEXT, pid,  addr + i * 8, NULL);
    val = *(long *)(s + i * 8) | val;
    if (j != 0) 
    {
        ptrace(PTRACE_POKEDATA, pid, addr + i * 8, val);
    }
}