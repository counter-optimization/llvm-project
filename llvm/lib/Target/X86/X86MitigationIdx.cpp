#include <algorithm>
#include <cassert>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86FrameLowering.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "X86MachineFunctionInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"

#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/MC/MCContext.h"

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/DebugLoc.h"

#include "llvm/Pass.h"

using namespace llvm;

static cl::opt<bool> EnableIdx("x86-gen-idx",
                               cl::desc("Generate index for asm trace"),
                               cl::init(false));

namespace {

class X86_64MitigationIdxPass : public MachineFunctionPass {
public:
  static char ID;

  X86_64MitigationIdxPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    MachineFunctionPass::getAnalysisUsage(AU);
    AU.setPreservesCFG();
  }

  StringRef getPassName() const override {
    return "Support index for asm tarce";
  }
};

} // end anonymous namespace

bool X86_64MitigationIdxPass::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableIdx)
    return false;

  llvm::errs() << "Running IDX " << MF.getName() << "\n";
  bool doesModifyFunction = false;

  std::string SubName = MF.getName().str();

  int InstructionIdx = 0;
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      DebugLoc DL = MI.getDebugLoc();
      const auto &STI = MF.getSubtarget();
      auto *TII = STI.getInstrInfo();

      const MCInstrDesc &MIDesc = MI.getDesc();
      if (MIDesc.isPseudo()) {
        continue;
      }

      if (MIDesc.isCall()) {
        continue;
      }

      int CurIdx = InstructionIdx++;

      llvm::errs() << "InstructionIdx: " << CurIdx << " runnning on \n";
      BuildMI(MBB, MI, DL, TII->get(X86::SBB64ri32), X86::R11)
          .addReg(X86::R11)
          .addImm(CurIdx);

      // conftest hack
      if (false && MF.getName() == "main") {
          if (MIDesc.isReturn()) {
            BuildMI(MBB, MI, DL, TII->get(X86::SBB64ri32), X86::R11)
                .addReg(X86::R11)
                .addImm(0x9999999999);
            BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::RAX).addImm(0);
          }
      }
    }
  }
  return true;
}

char X86_64MitigationIdxPass::ID = 0;

FunctionPass *llvm::createX86_64MitigationIdxPass() {
  return new X86_64MitigationIdxPass();
}

INITIALIZE_PASS(X86_64MitigationIdxPass, "x86-gen-idx", "Index for asm trace",
                true, true)
