#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>

// g++ test_pwn_heap_rwx.cpp -z execstack
// ./a.out | grep 'heap'
// check heap permission is rwx

int main() {
  pid_t pid = getpid();
  printf("pid %d\n", pid);
  new int[10];
  std::string command = "cat /proc/" + std::to_string(pid) + "/maps";
  system(command.c_str());

  return 0;
}
