#include "rvemu.h"

enum exit_reason_t machine_step(machine_t *m) {
  while(true) {
    m->state.exit_reason = none;
    exec_block_interp(&m->state);
    assert(m->state.exit_reason != none);
    if (m->state.exit_reason == indirect_branch ||
        m->state.exit_reason == direct_branch) {
          continue; 
        }
    break;
  }
  m->state.pc = m->state.reenter_pc;
  assert(m->state.exit_reason == ecall);
  return ecall;
}

void machine_load_program(machine_t *m, char *prog) {
  int fd = open(prog, O_RDONLY);
  if (fd == -1) {
    fatal(strerror(errno));
  }

  mmu_load_elf(&m->mmu, fd);
  close(fd);
  m->state.pc = m->mmu.entry;
}

void machine_setup(machine_t *m, int argc, char *argv[]) {
  size_t stack_size = 32 * 1024 * 1024;
  u64 stack = mmu_alloc(&m->mmu, stack_size);
  m->state.gp_regs[sp] = stack + stack_size;
  m->state.gp_regs[sp] -= 8; // auxv 
  m->state.gp_regs[sp] -= 8; // envp 
  m->state.gp_regs[sp] -= 8; // argv 
  u64 args = argc - 1;
  
}
