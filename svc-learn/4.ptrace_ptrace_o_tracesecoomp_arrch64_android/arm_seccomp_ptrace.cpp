
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/prctl.h>

#include <signal.h>
#include <errno.h>

#include <unistd.h>



#include <elf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <asm/ptrace.h>
#include <asm-generic/unistd.h> //???

static void process_signals(pid_t child);
static int wait_for_open(pid_t child);
static void read_file_name(pid_t child, char *file,struct user_pt_regs regs);
static void redirect_file(pid_t child, const char *file,struct user_pt_regs regs);
void putdata(pid_t pid, char* addr, char * str, long sz);

const int long_size = sizeof(long);

int main()
{
    pid_t pid;
    int status;
    if ((pid = fork()) == 0) 
    {
        //子进程
        ptrace(PTRACE_TRACEME, 0, 0, 0);

        // ====== 配置seccomp
        struct sock_filter filter[] = 
        {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE), //__NR_openat就跟踪,,怎么个跟踪法子???
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), //其它就运行
        };
        struct sock_fprog prog = 
        {
            .filter = filter,
            .len = (unsigned short) (sizeof(filter)/sizeof(filter[0])),
        };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) 
        {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return 1;
        }
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) 
        {
            perror("when setting seccomp filter");
            return 1;
        }

        // ====== 自我停止
        kill(getpid(), SIGSTOP);


        ssize_t count;
        char buf[256];
        int fd;
        fd = syscall(__NR_openat,fd,"/data/local/tmp/flag.txt", O_RDONLY);
        if (fd == -1) //flag文件
        {
            perror("open");
            return 1;
        }
        while((count = syscall(__NR_read, fd, buf, sizeof(buf))) > 0) //读到buf
        {
            syscall(__NR_write, STDOUT_FILENO, buf, count);//写到std_out
        }
        syscall(__NR_close, fd);//关闭句柄
        printf("\n");
    } 
    else 
    {
        //父进程
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
        //表示要跟踪seccomp事件。当被跟踪的进程触发一个seccomp事件时，它会暂停执行，等待跟踪它的进程做出响应
        process_signals(pid);
        return 0;
    }
}

static void process_signals(pid_t child_pid)
{
    int status;
    const char* file_to_avoid = "/data/local/tmp/flag.txt";
    const char* file_to_redirect ="/data/local/tmp/hacker.txt";
    while(1) 
    {
        char orig_file[256];
        struct user_pt_regs regs;
        struct iovec io;
        io.iov_base = &regs;
        io.iov_len = sizeof(regs);
        ptrace(PTRACE_CONT, child_pid, 0, 0);//第一次 放行 kill(getpid(), SIGSTOP), 之后放行
        waitpid(child_pid, &status, 0); 
        ptrace(PTRACE_GETREGSET, child_pid, (void*)NT_PRSTATUS/*type*/, &io);
        printf("syscall num : %llu \n",regs.regs[8]);//r8/x8?
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) )
        {
            switch (regs.regs[8])
            {

            case __NR_openat:
                read_file_name(child_pid, orig_file,regs);//读取文件名
                printf("[Openiat %s]\n", orig_file);
                if (strcmp(file_to_avoid, orig_file) == 0)//是不是hook的文件
                {
                    putdata(child_pid,(char*)regs.regs[1],(char*)file_to_redirect,strlen(file_to_redirect)+1);
                }
            }
        }
            
        if (WIFEXITED(status))
        {
            break;
        }
    }
}


static void read_file_name(pid_t child, char *file, struct user_pt_regs regs)
{
    char *child_addr;
    int i;
    child_addr = (char *) regs.regs[1];
    do 
    {
        long val;
        char *p;
        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1) 
        {
            fprintf(stderr, "PTRACE_PEEKTEXT error: %s", strerror(errno));
            exit(1);
        }
        child_addr += sizeof (long);
        p = (char *) &val;
        for (i = 0; i < sizeof (long); ++i, ++file) 
        {
            *file = *p++;
            if (*file == '\0') break;
        }
    } while (i == sizeof (long));
}


void putdata(pid_t pid, char* addr, char * str, long sz)
{
    printf("pid : %d  addr : %p str : %s sz : %ld \n",pid,addr,str,sz);
    int i = 0, j = sz / long_size;
    char *s = str;
    while (i < j) 
    {
        ptrace(PTRACE_POKEDATA, pid, addr + i * 8, *(long *)(s + i * 8));
        ++ i;
    }
    j = sz % long_size;
    if (j != 0) 
    {
        ptrace(PTRACE_POKEDATA, pid, addr + i * 8, *(long *)(s + i * 8));
    }
}

/*
===
C:/trace-seccomp-arrch64
λ clang++ -target aarch64-linux-android29 arm_seccomp_ptrace.cpp -o tuziseccomp -static-libstdc++
C:/trace-seccomp-arrch64
λ adb push .\tuziseccomp /data/local/tmp
====
PBCM10:/data/local/tmp $ chmod a+x tuziseccomp
PBCM10:/data/local/tmp $ ./tuziseccomp
syscall num : 56
[Openiat /data/local/tmp/flag.txt]
pid : 20572  addr : 5559d50940 str : /data/local/tmp/hacker.txt sz : 27
hacker{you was hacked!!!}
syscall num : 56
*/