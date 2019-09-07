/*
 * Usage: waitpid [OPTION]... [--] PID...
 * Wait until all PIDs exit.
 */

static const char WAITPID_HELP_TEXT[] = \
R"END(Usage: waitpid [OPTION]... [--] PID...
Wait until all PIDs exit.

waitpid(1) accepts a list of process IDs and then checks them for
termination.  When all PIDs terminate, waitpid(1) exits.  Optionally,
waitpid(1) will also display exit codes.

OPTIONS
  -D DELAY  (default: 0.5)
        Set delay in seconds between polling events for each PID.
        When not on Windows, and CODE is set to anything other than `ignore`,
        DELAY means nothing because instead of kill(2) polling, ptrace(2)
        syscall intercept is done instead.
  -C CODE   (default: ignore)
        Choose what to do with exit codes after all PIDs terminate.
        0, ignore ... waitpid(1) will return 0.  Never uses ptrace(2).
        (integer N) . waitpid(1) will return exit code of the N-th PID as
                      specified on the command line, starting from 1.
        min, max .... waitpid(1) will return the least/largest code.
        print ....... waitpid(1) will print pairs "PID: EXIT_CODE" in order
                      of PIDs specified on the command line, and return 0.
)END";


#if    defined(_WIN32)
#elif  defined(__linux__)
#elif  defined(__FreeBSD__)
#else
# warning "Unsupported platform"
#endif


extern "C" {
#if    defined(__unix__)
# include <unistd.h>
# include <sysexits.h>
# include <signal.h>
# include <sys/wait.h>
#endif

#if    defined(__linux__)
# include <sys/user.h>
# include <sys/ptrace.h>
#elif  defined(__FreeBSD__)
# include <sys/cdefs.h>
# include <machine/reg.h>
# include <sys/types.h>
# include <sys/ptrace.h>
#elif  defined(_WIN32)
# include <windows.h>
# include <synchapi.h>
#endif
}


#include  <cerrno>
#include  <cstring>
#include  <cstdio>
#include  <cstdlib>

#include  <iostream>
#include  <vector>
#include  <string>
#include  <chrono>
#include  <algorithm>
#include  <functional>
#include  <stdexcept>
#include  <limits>


#if    defined(_WIN32)
# include <getopt.h>
# include "mingw.thread.h"
# include "mingw.mutex.h"
#else
# include <thread>
# include <mutex>
#endif


using st = std::vector<int>::size_type;
#define TO_SIZE(e)  static_cast<st>(e)
#define STRERROR  strerror(errno)
// all this so i don't have to build a new mingw which supports __VA_OPT__
template<typename ...Ts>
void __COMPLAIN(const char *func, int line, const char *format, Ts... args) {
  fprintf(stderr, "waitpid[%s#%d]: ", func, line);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
  fprintf(stderr, format, args...);
#pragma GCC diagnostic pop
  fprintf(stderr, "\n");
  fflush(stderr);
}
#define COMPLAIN(...)  __COMPLAIN(__func__, __LINE__, __VA_ARGS__)
#define DIE(status, ...)  do{COMPLAIN(__VA_ARGS__);exit(status);}while(0)


#define  MSGWFSOFAIL          \
  "FATAL: WaitForSingleObject failed"
#define  MSGGECPFAIL          \
  "FATAL: GetExitCodeProcess failed: last error is %u"
#define  MSGPTRACEATTACHFAIL  \
  "FATAL: ptrace(2) attach for PID %d failed: %s"
#define  MSGWAITPIDUTFAIL     \
  "FATAL: waitpid(%d, NULL, WUNTRACED) failed: %s"
#define  MSGPTTOSCEUNKFAIL    \
  "FATAL: PT_TO_SCE failed, or could not PT_READ_D"
#define  MSGWAITPID0FAIL      \
  "FATAL: waitpid(%d, 0, 0) failed: %s"
#define  MSGGETREGSFAIL       \
  "FATAL: ptrace(2) register inspection for PID %d failed: %s"
#define  MSGSYSEXITS          \
  "NOTE: PID %d has exited with a possible sysexits.h value: %s (exit status %d)"
#define  MSGWIN32UNUSUALEXIT  \
  "NOTE: PID %d has exited unusually: %s (exit status 0x%04X/%d)"
#define  MSGSYSKILL           \
  "WARNING: PID %d terminated by signal, assuming 128+SIGNAL: %d"
#define  MSGBADRETCODE        \
  "ERROR: Failed to determine return code of PID %d, assuming 255"
#define  MSGINVALIDDELAY      \
  "FATAL: Could not interpret argument as a valid delay in seconds: -D%s"
#define  MSGINVALIDCODE       \
  "FATAL: Could not interpret argument as a valid code operation: -C%s"
#define  MSGPIDIDXTOOLARGE    \
  "FATAL: PID index larger than number of PIDs: -C%d"
#define  MSGGETOPTNOARG       \
  "FATAL: Option argument missing: -%c"
#define  MSGGETOPTUNKOPT      \
  "FATAL: Unknown option: -%c"
#define  MSGGETOPTUNK         \
  "FATAL: Unknown getopt(3) failure"
#define  MSGNOPIDS            \
  "FATAL: No PIDs specified"
#define  MSGINVALIDPID        \
  "FATAL: Could not interpret argument as a valid PID: %s"
#define  MSGWIN32MOD4WARN     \
  "WARNING: PID is not a multiple of 4 and is likely incorrect: %d"


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
using pid_t =
#if    defined(_WIN32)
  int
#elif  defined(__unix__)
  pid_t
#endif
;
#pragma GCC diagnostic pop

static std::mutex iomtx;

void dsleep(double secs) {
  auto delay = std::chrono::microseconds(static_cast<long>(secs*1'000'000));
  std::this_thread::sleep_for(delay);
}


#if    defined(_WIN32)
struct win32ntstatus {
  DWORD       rc;
  const char* macro;
};

/* The following is a non-exhaustive list of possible *abnormal termination*
 * exit codes.  waitpid(1) must only warn about well-known exit codes which are
 * either set by the operating system or the runtime, or are unique convention.
 * On Windows, all these codes are from NTSTATUS;  WinError codes
 * are apparently only returned by some processes, and we don't want to warn
 * about that.
 *
 * REFERENCES:
 * [1] List of peculiar exit codes on Windows:
 *   https://peteronprogramming.wordpress.com/2018/05/29/list-of-peculiar-exit-codes-on-windows/
 *
 * [2] NTSTATUS documentation:
 *   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
 *
 * [3] NTSTATUS values, tab separated:
 *   https://gist.github.com/interruptinuse/3a8211e3aa9f6b660844d2f0b1bc303c
 *
 * [4] Windows System Error Codes:
 *   https://www.symantec.com/connect/articles/windows-system-error-codes-exit-codes-description
 *
 * [5] MsiExec.exe and InstMsi.exe Error Messages:
 *   https://docs.microsoft.com/en-us/windows/win32/msi/error-codes
 */
static win32ntstatus win32ntstatuses[] = {
  { 0xC000013A, "STATUS_CONTROL_C_EXIT (interrupted by user)" },
  { 0x00000001, "terminated by process manager" },
  { 0x00000003, "CRT abort" },
  { 0x40000015, "STATUS_FATAL_APP_EXIT, or CRT abort" },
  { 0x40010004, "DBG_TERMINATE_PROCESS, or killed on system shutdown" },
  { 0xC0000409, "STATUS_STACK_BUFFER_OVERRUN, or a fastfail exception" },
  { 0x000000FF, "terminated with error reporting" },
  { 0xCFFFFFFF, "terminated as non-responsive" },

  /* XXX: I'm not sure if any status code below this comment will be set by the
   * system and as such should be reported as abnormal, but I've added the most
   * plausible-looking codes anyway. */

  /* uncategorized status codes */
  { 0xC0000001, "STATUS_UNSUCCESSFUL" },
  { 0xC0000005, "STATUS_ACCESS_VIOLATION" },
  { 0xC000001D, "STATUS_ILLEGAL_INSTRUCTION" },
  { 0xC000014B, "STATUS_PIPE_BROKEN" },
  { 0xC0000006, "STATUS_IN_PAGE_ERROR" },
  { 0xC0000007, "STATUS_PAGEFILE_QUOTA" },
  { 0xC0000009, "STATUS_BAD_INITIAL_STACK" },
  { 0xC000000A, "STATUS_BAD_INITIAL_PC" },
  { 0xC0000144, "STATUS_UNHANDLED_EXCEPTION" },
  { 0xC0000135, "STATUS_DLL_NOT_FOUND" },
  { 0xC0000142, "STATUS_DLL_INIT_FAILED" },
  { 0x00000116, "STATUS_CRASH_DUMP" },
  { 0x40000023, "STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE" },
  { 0x80000003, "STATUS_BREAKPOINT" },

  /* SEH exceptions */
  { 0x80000002, "STATUS_DATATYPE_MISALIGNMENT" },
  { 0x80000004, "STATUS_SINGLE_STEP" },
  { 0xC000008D, "STATUS_FLOAT_DENORMAL_OPERAND" },
  { 0xC000008E, "STATUS_FLOAT_DIVIDE_BY_ZERO" },
  { 0xC000008F, "STATUS_FLOAT_INEXACT_RESULT" },
  { 0xC0000090, "STATUS_FLOAT_INVALID_OPERATION" },
  { 0xC0000091, "STATUS_FLOAT_OVERFLOW" },
  { 0xC0000092, "STATUS_FLOAT_STACK_CHECK" },
  { 0xC0000093, "STATUS_FLOAT_UNDERFLOW" },
  { 0xC00002B4, "STATUS_FLOAT_MULTIPLE_FAULTS" },
  { 0xC00002B5, "STATUS_FLOAT_MULTIPLE_TRAPS" },

  /* memory exceptions */
  { 0x80000001, "STATUS_GUARD_PAGE_VIOLATION" },
  { 0x80000005, "STATUS_BUFFER_OVERFLOW" },
  { 0xC0000017, "STATUS_NO_MEMORY" },
  { 0xC000001A, "STATUS_UNABLE_TO_FREE_VM" },
  { 0xC0000022, "STATUS_ACCESS_DENIED" },
  { 0xC0000023, "STATUS_BUFFER_TOO_SMALL" },
  { 0xC0000025, "STATUS_NONCONTINUABLE_EXCEPTION" },
  { 0xC0000026, "STATUS_INVALID_DISPOSITION" },
  { 0xC0000027, "STATUS_UNWIND" },
  { 0xC0000028, "STATUS_BAD_STACK" },
  { 0xC0000029, "STATUS_INVALID_UNWIND_TARGET" },
  { 0xC000002A, "STATUS_NOT_LOCKED" },
  { 0xC000002B, "STATUS_PARITY_ERROR" },
  { 0xC000002C, "STATUS_UNABLE_TO_DECOMMIT_VM" },
  { 0xC000002D, "STATUS_NOT_COMMITTED" },
};

template<class T, size_t N>
constexpr size_t arraysize(T (&)[N]) { return N; }

struct win32ntstatus win32_unusual_exit(DWORD rc) {
  for(auto d: win32ntstatuses) {
    if(rc == d.rc) {
      return d;
    }
  }

  return {0, ""};
}
#endif


#if    defined(__unix__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wglobal-constructors"
#pragma clang diagnostic ignored "-Wexit-time-destructors"
static std::string sysexits[] = {
  "EX_USAGE",       // 64
  "EX_DATAERR",     // 65
  "EX_NOINPUT",     // 66
  "EX_NOUSER",      // 67
  "EX_NOHOST",      // 68
  "EX_UNAVAILABLE", // 69
  "EX_SOFTWARE",    // 70
  "EX_OSERR",       // 71
  "EX_OSFILE",      // 72
  "EX_CANTCREAT",   // 73
  "EX_IOERR",       // 74
  "EX_TEMPFAIL",    // 75
  "EX_PROTOCOL",    // 76
  "EX_NOPERM",      // 77
  "EX_CONFIG",      // 78
};
#pragma clang diagnostic pop

std::string unix_sysexit(int rc) {
  if(rc >= EX__BASE && rc <= EX__MAX) {
    return sysexits[rc-EX__BASE];
  }

  return "";
}
#endif


int waitpidnorc(pid_t pid, double delay) {
#if    defined(_WIN32)
  DWORD rc = 0;
  HANDLE ph = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
                          FALSE,
                          static_cast<DWORD>(pid));
  DWORD ws = WaitForSingleObject(ph, INFINITE);

  if(ws == WAIT_FAILED) {
    DIE(EXIT_FAILURE, MSGWFSOFAIL);
  }

  if(GetExitCodeProcess(ph, &rc) == FALSE) {
    DIE(EXIT_FAILURE, MSGGECPFAIL, GetLastError());
  }

  return rc;
#elif  defined(__unix__)
retry:
  errno = 0;
  int result = kill(pid, 0);

  if(!result || (result && errno != ESRCH)) {
    dsleep(delay);
    goto retry;
  }

  return 0;
#endif
}

int waitpidrc(pid_t pid, double delay) {
#if    defined(_WIN32)
  return waitpidnorc(pid, delay);
#elif  defined(__linux__)
  errno = 0;

  int status = 0;

  errno = 0;
  if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
    DIE(EXIT_FAILURE, MSGPTRACEATTACHFAIL, pid, STRERROR);
  }

  errno = 0;
  if(waitpid(pid, &status, 0) != pid) {
    DIE(EXIT_FAILURE, MSGWAITPID0FAIL, pid, STRERROR);
  }

  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXIT);
  ptrace(PTRACE_CONT,       pid, 0, 0);

  while(true) {
    errno = 0;
    if(waitpid(pid, &status, 0) != pid) {
      DIE(EXIT_FAILURE, MSGWAITPID0FAIL, pid, STRERROR);
    }

    int  signal     = 0;
    int  wstopsig   = 0;
    bool wifstopped = false;

    if((wstopsig = WSTOPSIG(status))) {
      wifstopped = !!WIFSTOPPED(status);

      switch(wstopsig) {
      case (SIGTRAP | 0x80):
        /* a syscall-stop, ignore */
        break;
      case SIGTRAP: /* tracer event */
        if(status & (PTRACE_EVENT_EXIT << 8)) {
          struct user_regs_struct regs;
          errno = 0;
          if(ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            DIE(EXIT_FAILURE, MSGGETREGSFAIL, pid, STRERROR);
          }

#if       defined(__i386)
          switch(regs.orig_eax) {
          case 0x25: // sys_kill
            // depends on the shell but 128+SIGNAL is most popular
            regs.ebx = 128+regs.ecx;
            COMPLAIN(MSGSYSKILL, pid, static_cast<int>(regs.ebx));
            [[fallthrough]];
          case 0x01: // sys_exit
            [[fallthrough]];
          case 0xFC: // sys_exit_group
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return static_cast<int>(regs.ebx);
          }
#elif     defined(__x86_64__)
          switch(regs.orig_rax) {
          case 0x3e: // sys_kill
            // depends on the shell but 128+SIGNAL is most popular
            regs.rdi = 128+regs.rsi;
            COMPLAIN(MSGSYSKILL, pid, static_cast<int>(regs.rdi));
            [[fallthrough]];
          case 0x3C: // sys_exit
            [[fallthrough]];
          case 0xE7: // sys_exit_group
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return static_cast<int>(regs.rdi);
          }
#else
# error "Unsupported architecture for GNU/Linux"
#endif
          unsigned long retcode = std::numeric_limits<unsigned long>::max();
          ptrace(PTRACE_GETEVENTMSG, pid, 0, &retcode);

          // If we're handling PTRACE_EVENT_EXIT and WIFSTOPPED(status) is true,
          // the process has received a terminating signal.  This is the same
          // situation as with sys_kill handling above.
          if(wifstopped) {
            COMPLAIN(MSGSYSKILL, pid, static_cast<int>(128+retcode));
            return static_cast<int>(128+retcode);
          }

          // if retcode is set to our default, set it to 255, which is basically
          // the "everything failed" return value
          if(retcode == std::numeric_limits<unsigned long>::max()) {
            COMPLAIN(MSGBADRETCODE, pid);
            retcode = std::numeric_limits<unsigned char>::max();
          }

          return static_cast<int>(retcode);
        }

        break;
      case SIGSTOP:
      case SIGTSTP:
      case SIGTTIN:
      case SIGTTOU:
        [[fallthrough]];
      default:
        signal = WSTOPSIG(status);
      }
    }

    ptrace(PTRACE_CONT, pid, 0, signal);
  }
#elif     defined(__FreeBSD__)
  struct reg registers;

  errno = 0;
  if(ptrace(PT_ATTACH, pid, (caddr_t)0, SIGSTOP)) {
    DIE(EXIT_FAILURE, MSGPTRACEATTACHFAIL, pid, STRERROR);
  }

  int status = 0;

  if(waitpid(pid, &status, WUNTRACED) != pid) {
    DIE(EXIT_FAILURE, MSGWAITPIDUTFAIL, pid, STRERROR);
  }

  // TODO: should probably send SIGSTOP from all ptraces starting here and
  // TODO: until PT_READ_D, which should resume the process
  while(ptrace(PT_TO_SCE, pid, (caddr_t)1, 0) == 0) {
    if(wait(0) == -1) {
      break;
    }

    errno = 0;
    if(ptrace(PT_GETREGS, pid, (caddr_t)&registers, 0)) {
      DIE(EXIT_FAILURE, MSGGETREGSFAIL, pid, STRERROR);
    }

#if       defined(__i386__)
# define SCNUM  r_eax
# define STPTR  r_esp
#elif     defined(__x86_64__)
# define SCNUM  r_rax
# define STPTR  r_rsp
#else
# error "Unsupported architecture"
#endif
    if(registers.SCNUM == 1) { // exit syscall
      int rc = ptrace(PT_READ_D, pid, (caddr_t)registers.STPTR+sizeof(int), 0);
      ptrace(PT_DETACH, pid, (caddr_t)1, 0);
      return rc;
    }
  }

  DIE(EXIT_FAILURE, MSGPTTOSCEUNKFAIL);
#else
  return 0;
# warn "Exit code inspection not supported on this platform"
#endif
}

int waiter(pid_t pid, double delay, bool checkrc,
           std::function<void(int)> callback) {
  int rc = (checkrc ? waitpidrc : waitpidnorc)(pid, delay);

  if(checkrc) {
    callback(rc);
  }

  return rc;
}

int process_codes(std::vector<int>& codes, std::vector<pid_t>& pids, int op) {
  switch(op) {
  case 0:
    return 0;
  case -1:
    return *std::min_element(codes.begin(), codes.end());
  case -2:
    return *std::max_element(codes.begin(), codes.end());
  case -3:
    for(st i = 0; i < codes.size(); i++) {
      std::cout << pids[i] << ": " << codes[i] << std::endl;
    }

    return 0;
  default:
    if(op < -3 || TO_SIZE(op) > codes.size()) {
      return -1;
    }

    return codes[TO_SIZE(op)-1];
  }
}


int main(int argc, char **argv) {
  std::vector<pid_t> pids;
  std::vector<std::thread> threads;
  std::vector<int> codes;
  double delay = 0.5;
  int op = 0;
  bool checkrc = false;

  int opt;
  while((opt = getopt(argc, argv, ":D:C:h")) !=
#if       defined(_WIN32)
    EOF
#else
    -1
#endif // defined(_WIN32)
) {switch(opt) {
    case 'D': {
      errno = 0;
      double d = strtod(optarg, nullptr);

      if(errno || d <= 0) {
        DIE(2, MSGINVALIDDELAY, optarg);
      }

      delay = d;
      break;
    }
    case 'C': {
      std::string ops(optarg);

      if(ops == "ignore") { op =  0; break; }
      if(ops ==    "min") { op = -1; break; }
      if(ops ==    "max") { op = -2; break; }
      if(ops ==  "print") { op = -3; break; }

      char *endptr;
      errno = 0;
      op = static_cast<int>(strtol(optarg, &endptr, 0));

      if(errno || op < 0 || endptr == optarg) {
        DIE(2, MSGINVALIDCODE, optarg);
      }

      break;
    }
    case 'h':
      std::cerr << WAITPID_HELP_TEXT;
#ifndef PACKAGE_STRING
#define PACKAGE_STRING "waitpid"
#endif // PACKAGE_STRING
      std::cerr << PACKAGE_STRING << std::endl;
      exit(EXIT_FAILURE);
    case ':':
      DIE(2, MSGGETOPTNOARG, optopt);
    case '?':
      DIE(2, MSGGETOPTUNKOPT, optopt);
    default:
      DIE(2, MSGGETOPTUNK);
    }
  }

  if(optind >= argc) {
    DIE(2, MSGNOPIDS);
  }

  checkrc = !!op;

  const size_t pid_count = TO_SIZE(argc)-TO_SIZE(optind);
  codes.resize(pid_count, -1);

  if(op > 0 && TO_SIZE(op) > pid_count) {
    DIE(2, MSGPIDIDXTOOLARGE, op);
  }

  for(st i = TO_SIZE(optind); i < TO_SIZE(argc); i++) {
    errno = 0;
    pid_t pid = static_cast<pid_t>(strtol(argv[i], nullptr, 0));

    if(errno || pid <= 0) {
      DIE(2, MSGINVALIDPID, argv[i]);
    }

#if       defined(_WIN32)
    if(pid % 4) {
      COMPLAIN(MSGWIN32MOD4WARN, static_cast<int>(pid));
    }
#endif // defined(_WIN32)

    pids.push_back(pid);

    threads.emplace_back(waiter, pid, delay, checkrc, [=, &codes](int rc) {
      std::lock_guard lock(iomtx);

      codes[i-TO_SIZE(optind)] = rc;

#if       defined(_WIN32)
      win32ntstatus d = win32_unusual_exit(rc);

      if(d.rc != 0) {
        COMPLAIN(MSGWIN32UNUSUALEXIT, pid, d.macro, d.rc, d.rc);
      }
#elif     defined(__unix__)
      std::string sysexit = unix_sysexit(rc);

      if(sysexit != "") {
        COMPLAIN(MSGSYSEXITS, pid, sysexit.c_str(), rc);
      }
#endif
    });
  }

  for(std::thread& t : threads) {
    t.join();
  }

  return process_codes(codes, pids, op);
}
