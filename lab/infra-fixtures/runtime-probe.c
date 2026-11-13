#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/resource.h>
int main(void) {
  char line[256]; unsigned long long caps = 1; int nnp = 0;
  FILE *status = fopen("/proc/self/status", "r");
  if (!status) return 2;
  while (fgets(line, sizeof line, status)) {
    if (!strncmp(line, "CapEff:", 7)) sscanf(line + 7, "%llx", &caps);
    if (!strncmp(line, "NoNewPrivs:", 11)) sscanf(line + 11, "%d", &nnp);
  }
  fclose(status);
  struct rlimit limit; if (getrlimit(RLIMIT_CORE, &limit)) return 2;
  int rootfd = open("/write-denied", O_WRONLY | O_CREAT, 0600);
  int tempfd = open("/tmp/write-allowed", O_WRONLY | O_CREAT, 0600);
  int ok = getuid() == 65532 && rootfd < 0 && tempfd >= 0 && caps == 0 && nnp == 1 && limit.rlim_cur == 0 && access("/bin/sh", F_OK) != 0 && access("/var/run/docker.sock", F_OK) != 0;
  if (tempfd >= 0) close(tempfd);
  printf("{\"ok\":%s,\"uid\":%d,\"rootWriteDenied\":%s,\"tmpWriteAllowed\":%s,\"capEffZero\":%s,\"noNewPrivileges\":%s,\"coreLimitZero\":%s,\"shellAbsent\":%s,\"dockerSocketAbsent\":%s}\n", ok?"true":"false", getuid(), rootfd<0?"true":"false", tempfd>=0?"true":"false", caps==0?"true":"false", nnp==1?"true":"false", limit.rlim_cur==0?"true":"false", access("/bin/sh", F_OK)!=0?"true":"false", access("/var/run/docker.sock", F_OK)!=0?"true":"false");
  return ok ? 0 : 1;
}
