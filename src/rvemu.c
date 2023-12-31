#include <stdio.h> 
#include "rvemu.h"

int main(int argc, char* argv[]) {
  assert(argc > 1);
  machine_t machine = {0};
  machine_load_program(&machine, argv[1]);
  //printf("muchine.mmu.entry: %lx\n", machine.mmu.host_alloc);
  machine_setup(&machine, argc, argv);
  while (true) {
    enum exit_reason_t reason = machine_step(&machine);
    assert(reason == ecall);
  }
  return 0;
}
