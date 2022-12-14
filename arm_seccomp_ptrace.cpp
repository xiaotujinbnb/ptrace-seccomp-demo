#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <sys/ptrace.h>

#include <sys/reg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <fcntl.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

#include "Syscall_arm64.h"
#include "arm64_seccomp.h"

const int long_size = sizeof(long);

int main()
{
    pid_t pid;
    int status;
    if ((pid = fork()) == 0) {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 1),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
            .filter = filter,
            .len = (unsigned short) (sizeof(filter)/sizeof(filter[0])),
        };
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return 1;
        }
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
            perror("when setting seccomp filter");
            return 1;
        }
        kill(getpid(), SIGSTOP);
        ssize_t count;
        char buf[256];
        int fd;
        fd = syscall(__NR_openat,fd,"/data/local/tmp/tuzi1.txt", O_RDONLY);
        syscall(__NR_openat,fd,"/data/local/tmp/asdss.txt", O_RDONLY);
        syscall(__NR_openat,fd,"/data/local/tmp/asda.txt", O_RDONLY);
        syscall(__NR_openat,fd,"/data/local/tmp/TsdsaWO.txt", O_RDONLY);
        syscall(__NR_openat,fd,"/data/local/tmp/sadas.txt", O_RDONLY);
        syscall(__NR_openat,fd,"/data/local/tmp/sad.txt", O_RDONLY);
        syscall(__NR_openat,fd,"/data/local/tmp/asda.txt", O_RDONLY);
        if (fd == -1) {
            perror("open");
            return 1;
        }
        while((count = syscall(__NR_read, fd, buf, sizeof(buf))) > 0) {
            syscall(__NR_write, STDOUT_FILENO, buf, count);
        }
        syscall(__NR_close, fd);
        
    } else {
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
        process_signals(pid);
        return 0;
    }
}

static void process_signals(pid_t child)
{
    char file_to_redirect[256] = "/data/local/tmp/tuzi1.txt";
    char file_to_avoid[256] = "/data/local/tmp/tuzi.txt";
    int status;
    while(1) {
        char orig_file[PATH_MAX];
        struct user_pt_regs regs;
        struct iovec io;
        io.iov_base = &regs;
        io.iov_len = sizeof(regs);
        ptrace(PTRACE_CONT, child, 0, 0);
        waitpid(child, &status, 0);
        ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &io);
        printf("syscall num : %llu \n",regs.regs[8]);
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) ){
            switch (regs.regs[8])
            {
            case __NR_openat:
                read_file(child, orig_file,regs);
                printf("[Openiat %s]\n", orig_file);
                if (strcmp(file_to_avoid, orig_file) == 0){
                    putdata(child,regs.regs[1],file_to_redirect,strlen(file_to_avoid)+1);
                }
            }
        }
            
        if (WIFEXITED(status)){
            break;
        }
    }
}


static void read_file(pid_t child, char *file,user_pt_regs regs)
{
    char *child_addr;
    int i;
    child_addr = (char *) regs.regs[1];
    do {
        long val;
        char *p;
        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1) {
            fprintf(stderr, "PTRACE_PEEKTEXT error: %s", strerror(errno));
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


void putdata(pid_t pid, uint64_t addr, char * str, long sz)
{
    printf("pid : %d  addr : %lx str : %s sz : %ld \n",pid,addr,str,sz);
    int i = 0, j = sz / long_size;
    char *s = str;
    while (i < j) {
        ptrace(PTRACE_POKEDATA, pid, addr + i * 8, *(long *)(s + i * 8));
        ++ i;
    }
    j = sz % long_size;
    if (j != 0) {
        ptrace(PTRACE_POKEDATA, pid, addr + i * 8, *(long *)(s + i * 8));
    }
}
