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

static cl::opt<bool> EnableDeIdx("x86-gen-deidx",
                                 cl::desc("Generate index for asm trace"),
                                 cl::init(false));

namespace {

class X86_64MitigationDeIdxPass : public MachineFunctionPass {
public:
  static char ID;

  X86_64MitigationDeIdxPass() : MachineFunctionPass(ID) {}

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

bool X86_64MitigationDeIdxPass::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableDeIdx)
    return false;

  llvm::outs() << "Running DeIdx pass on " << MF.getName() << "\n";
  bool doesModifyFunction = false;

  std::string SubName = MF.getName().str();

  std::vector<MachineInstr *> SBB;
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      DebugLoc DL = MI.getDebugLoc();
      const auto &STI = MF.getSubtarget();
      auto *TII = STI.getInstrInfo();

      const MCInstrDesc &MIDesc = MI.getDesc();
      if (MIDesc.isPseudo()) {
        continue;
      }
      // if MI is SBB with R11
      if (MI.getOpcode() == X86::SBB64ri32) {
        if (MI.getOperand(0).getReg() == X86::R11) {
          SBB.push_back(&MI);
        }
      }
    }
  }
  for (auto &MI : SBB) {
    MI->eraseFromParent();
  }
  return true;
}

char X86_64MitigationDeIdxPass::ID = 0;

FunctionPass *llvm::createX86_64MitigationDeIdxPass() {
  return new X86_64MitigationDeIdxPass();
}

INITIALIZE_PASS(X86_64MitigationDeIdxPass, "x86-gen-deidx",
                "Index for asm trace", true, true)
