#include <asm/unistd_64.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>

void configure_seccomp()
{
    // struct sock_filter filter[] = {
    //     BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    //     BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 3),
    //     BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[2]))),
    //     BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY, 0, 1),
    //     BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    //     BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)};

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))), //L1
        //从 seccomp 数据中读取当前被调用的系统调用号
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 2),//L2
        //比较上一步加载的系统调用号与 __NR_openat 是否相等
        //相等的话,继续往下执行,跳转0步
        //不相等,跳转2步,到L5执行,SECCOMP_RET_ALLOW允许执行
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[2]))),//L3
        //读取arg2
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY, 0, 1),//L4
        //arg2是不是O_RDONLY
        //如果是,则SECCOMP_RET_ALLOW允许执行
        //如果不是,则跳转1步,SECCOMP_RET_KILL进程终止
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),//L5
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)//L6
    };
    //open()函数底层会调用__NR_openat,而不是


    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    printf("Configuring seccomp\n");
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main(int argc, char *argv[])
{
    int infd, outfd;
    ssize_t read_bytes;
    char buffer[1024];

    if (argc < 3)
    {
        printf("Usage:\n\tdup_file <input path> <output_path>\n");
        return -1;
    }
    printf("[*] cp '%s' to '%s'\n", argv[1], argv[2]);

    configure_seccomp(); // 配置seccomp

    if ((infd = open(argv[1], O_RDONLY)) > 0)
    {
        printf("[*] open(argv[1], O_RDONLY)=%d\n",  infd);
        if ((outfd = open(argv[2], O_WRONLY | O_CREAT, 0644)) > 0)
        {
            printf("[*] open(argv[2], O_WRONLY | O_CREAT, 0644)=%d\n",  infd);
            while ((read_bytes = read(infd, &buffer, 1024)) > 0)
                write(outfd, &buffer, (ssize_t)read_bytes);
        }
    }
    close(infd);
    close(outfd);
    printf("[*] work donw\n");
    return 0; 
}