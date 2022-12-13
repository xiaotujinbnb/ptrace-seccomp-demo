static void process_signals(pid_t child);
static int wait_for_open(pid_t child);
static void read_file(pid_t child, char *file,user_pt_regs regs);
static void redirect_file(pid_t child, const char *file,user_pt_regs regs);
void putdata(pid_t pid, uint64_t addr, char * str, long sz);


#if defined(__aarch64__)
	#define ARM_x0 regs[0]
    #define ARM_x1 regs[1]
    #define ARM_x2 regs[2]
	#define ARM_x8 regs[8]
	#define ARM_lr regs[30]
	#define ARM_sp sp
	#define ARM_pc pc
	#define ARM_cpsr pstate
	#define NT_PRSTATUS 1
	#define NT_foo 1
#endif
