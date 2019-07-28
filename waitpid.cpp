/*
 * Usage: waitpid [OPTION]... [--] PID...
 * Wait until all PIDs exit.
 *
 * waitpid(1) accepts a list of process IDs and then checks them for
 * termination.  When all PIDs terminate, waitpid(1) exits.  Optionally,
 * waitpid(1) will also display exit codes.
 *
 * OPTIONS
 *   -D DELAY  (default: 0.5)
 *         Set delay in seconds between polling events for each PID.
 *         When not on Windows, and CODE is set to anything other than `ignore`,
 *         DELAY means nothing because instead of kill(2) polling, ptrace(2)
 *         syscall intercept is done instead.
 *   -C CODE   (default: ignore)
 *         Choose what to do with exit codes after all PIDs terminate.
 *         0, ignore ... waitpid(1) will return 0.  Never uses ptrace(2).
 *         (integer N) . waitpid(1) will return exit code of the N-th PID as
 *                       specified on the command line, starting from 1.
 *         min, max .... waitpid(1) will return the least/largest code.
 *         print ....... waitpid(1) will print pairs "PID: EXIT_CODE" in order
 *                       of PIDs specified on the command line, and return 0.
 */

#if    defined(_WIN32)
#elif  defined(__linux__)
#elif  defined(__FreeBSD__)
#else
# warning "Unsupported platform"
#endif


extern "C" {
#if    defined(__linux__)
# include <sys/user.h>
# include <sys/ptrace.h>
#endif

#if    defined(__FreeBSD__)
# include <sys/cdefs.h>
# include <machine/reg.h>
# include <sys/types.h>
# include <sys/ptrace.h>
#endif

#if    defined(_WIN32)
# include <windows.h>
# include <synchapi.h>
#elif  defined(__unix__)
# define  _POSIX_C_SOURCE  200809L
# include <unistd.h>
# include <signal.h>
# include <sys/wait.h>
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


using std::vector;
using std::string;
using std::thread;
using std::function;


using st = vector<int>::size_type;
#define TO_SIZE(e)  static_cast<st>(e)
#define STRERROR  strerror(errno)
// all this so i don't have to build a new mingw which supports __VA_OPT__
template<typename ...Ts>
void __COMPLAIN(const char *file, const char *func, int line,
                const char *format, Ts... args) {
  fprintf(stderr, "%s[%s()#%d]: ", file, func, line);
  fprintf(stderr, format, args...);
  fprintf(stderr, "\n");
  fflush(stderr);
}
#define COMPLAIN(...)  __COMPLAIN(__FILE__, __func__, __LINE__, __VA_ARGS__)
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
#define  MSGSYSKILL           \
  "WARNING: PID %d terminated, intercepting sys_kill and assuming 128+SIGNAL: %d"
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


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
using pid_t =
#pragma clang diagnostic pop
#if    defined(_WIN32)
  int
#elif  defined(__unix__)
  pid_t
#endif
;

static std::mutex iomtx;
#define IOCRITICAL(...)  do {               \
  std::scoped_lock<std::mutex> lock(iomtx); \
  __VA_ARGS__ ;                             \
} while(0)

void dsleep(double secs) {
  auto delay = std::chrono::microseconds(static_cast<long>(secs*1'000'000));
  std::this_thread::sleep_for(delay);
}


int waitpidnorc(pid_t pid, double delay) {
#if    defined(_WIN32)
  DWORD rc = 0;
  HANDLE ph = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
                          FALSE,
                          static_cast<DWORD>(pid));
  DWORD ws = WaitForSingleObject(ph, INFINITE);

  if(ws == WAIT_FAILED)
    DIE(EXIT_FAILURE, MSGWFSOFAIL);

  if(GetExitCodeProcess(ph, &rc) == FALSE)
    DIE(EXIT_FAILURE, MSGGECPFAIL, GetLastError());

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
  if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    DIE(EXIT_FAILURE, MSGPTRACEATTACHFAIL, pid, STRERROR);

  errno = 0;
  if(waitpid(pid, &status, 0) != pid)
    DIE(EXIT_FAILURE, MSGWAITPID0FAIL, pid, STRERROR);

  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXIT);
  ptrace(PTRACE_CONT,       pid, 0, 0);

  while(true) {
    errno = 0;
    if(waitpid(pid, &status, 0) != pid)
      DIE(EXIT_FAILURE, MSGWAITPID0FAIL, pid, STRERROR);

    if((WSTOPSIG(status) == SIGTRAP) && (status & (PTRACE_EVENT_EXIT << 8))) {
      struct user_regs_struct regs;
      errno = 0;
      if(ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE(EXIT_FAILURE, MSGGETREGSFAIL, pid, STRERROR);

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

      // if retcode is set to our default, set it to 255, which is basically
      // the "everything failed" return value
      if(retcode == std::numeric_limits<unsigned long>::max()) {
        COMPLAIN(MSGBADRETCODE, pid);
        retcode = std::numeric_limits<unsigned char>::max();
      }

      return static_cast<int>(retcode);
    }

    ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status));
  }
#elif     defined(__FreeBSD__)
  struct reg registers;

  errno = 0;

  if(ptrace(PT_ATTACH, pid, (caddr_t)0, SIGSTOP))
    DIE(EXIT_FAILURE, MSGPTRACEATTACHFAIL, pid, STRERROR);

  int status = 0;
  if(waitpid(pid, &status, WUNTRACED) != pid)
    DIE(EXIT_FAILURE, MSGWAITPIDUTFAIL, pid, STRERROR);

  // TODO: should probably send SIGSTOP from all ptraces starting here and
  // TODO: until PT_READ_D, which should resume the process
  while(ptrace(PT_TO_SCE, pid, (caddr_t)1, 0) == 0) {
    if (wait(0) == -1)
      break;

    errno = 0;

    if(ptrace(PT_GETREGS, pid, (caddr_t)&registers, 0))
      DIE(EXIT_FAILURE, MSGGETREGSFAIL, pid, STRERROR);

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
           function<void(int)> callback) {
  int rc = (checkrc ? waitpidrc : waitpidnorc)(pid, delay);
  if(checkrc)
    callback(rc);
  return rc;
}

int process_codes(vector<int>& codes, vector<pid_t>& pids, int op) {
  switch(op) {
  case 0:
    return 0;
  case -1:
    return *std::min_element(codes.begin(), codes.end());
  case -2:
    return *std::max_element(codes.begin(), codes.end());
  case -3:
    for(st i = 0; i < codes.size(); i++)
      std::cout << pids[i] << ": " << codes[i] << std::endl;
    return 0;
  default:
    if(op < -3 || TO_SIZE(op) > codes.size())
      return -1;

    return codes[TO_SIZE(op)-1];
  }
}


int main(int argc, char **argv) {
  vector<pid_t> pids;
  vector<thread> threads;
  vector<int> codes;
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

      if(errno || d <= 0)
        DIE(EXIT_FAILURE, MSGINVALIDDELAY, optarg);

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

      if(errno || op < 0 || endptr == optarg)
        DIE(EXIT_FAILURE, MSGINVALIDCODE, optarg);

      break;
    }
    case 'h':
      std::cerr << R"END(Usage: waitpid [OPTION]... [--] PID...
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
#ifndef PACKAGE_STRING
#define PACKAGE_STRING "waitpid"
#endif // PACKAGE_STRING
std::cerr << PACKAGE_STRING << std::endl;
      exit(EXIT_FAILURE);
    case ':':
      DIE(EXIT_FAILURE, MSGGETOPTNOARG, optopt);
    case '?':
      DIE(EXIT_FAILURE, MSGGETOPTUNKOPT, optopt);
    default:
      DIE(EXIT_FAILURE, MSGGETOPTUNK);
    }
  }

  if(optind >= argc)
    DIE(EXIT_FAILURE, MSGNOPIDS);

  checkrc = !!op;

  const size_t pid_count = TO_SIZE(argc)-TO_SIZE(optind);
  codes.resize(pid_count, -1);

  if(op > 0 && TO_SIZE(op) > pid_count)
    DIE(EXIT_FAILURE, MSGPIDIDXTOOLARGE, op);

  for(st i = TO_SIZE(optind); i < TO_SIZE(argc); i++) {
    errno = 0;
    pid_t pid = static_cast<pid_t>(strtol(argv[i], nullptr, 0));

    if(errno || pid <= 0)
      DIE(EXIT_FAILURE, MSGINVALIDPID, argv[i]);

#if       defined(_WIN32)
    if(pid % 4)
      COMPLAIN(MSGWIN32MOD4WARN, static_cast<int>(pid));
#endif // defined(_WIN32)

    pids.push_back(pid);

    threads.emplace_back(waiter, pid, delay, checkrc, [&codes, i](int rc) {
      IOCRITICAL({ codes[i-TO_SIZE(optind)] = rc; });
    });
  }

  for(thread& t : threads)
    t.join();

  return process_codes(codes, pids, op);
}
