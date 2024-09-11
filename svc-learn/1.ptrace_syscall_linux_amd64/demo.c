//linux amd64 ELF 64-bit
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/fcntl.h>
#include <syscall.h>

void die(const char *msg)
{
    perror(msg);
    exit(errno);
}

void attack()
{
    syscall(SYS_getpid, SYS_mkdir, "dir", 0777);//这样些看上去有错,但只会调用2次syscall
	//syscall(SYS_getpid);
	//syscall(SYS_mkdir, "dir", 0777);
}

int main()
{
    int pid;
    struct user_regs_struct regs;
    switch ((pid = fork()))
    {

    case -1:
        die("Failed fork");
    case 0:
        //子进程
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);//当前进程停止,然后给tracer/father发送SIGSTOP
        attack();
        return 0;
    }

    //父进程
    waitpid(pid, 0, 0);//获取 kill(getpid(), SIGSTOP) 发过来的信号
    while (1)
    {
        int st;

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);//是让子进程继续执行，直到它到达下一个系统调用
		//子进程停止的时机是? 刚要执行调用,同时调用也被检查过是否可以被执行

		printf("[F]: F9\n");
        if (waitpid(pid, &st, __WALL) == -1)
        {
            break;
        }

        if (!(WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP))
        {
            printf("Unexpected wait status %x\n", st);
            break;
        }

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        

        if (regs.rax != -ENOSYS)
        {
			printf("[F]: normal syscall id(orig_rax) %lld\n", regs.orig_rax);
            continue;//正常的调用,放行
        }

		printf("[F]: exception syscall id(orig_rax) = %lld\n", regs.orig_rax);//进入内核时的原始系统调用号,即将执行的系统调用号
		//异常调用
        if (regs.orig_rax == SYS_getpid)//只处理我们自己故意做出的sys_getpid异常
        {
			//把syscall(SYS_getpid, SYS_mkdir, "dir", 0777)
			//变为syscall(SYS_mkdir, "dir", 0777)执行
            regs.orig_rax = regs.rdi;
            regs.rdi = regs.rsi;
            regs.rsi = regs.rdx;
            regs.rdx = regs.r10;
            regs.r10 = regs.r8;
            regs.r8 = regs.r9;
            regs.r9 = 0;//参数往上移动
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        }
    }
    return 0;
}
