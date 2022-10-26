#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86FrameLowering.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "X86MachineFunctionInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"

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

namespace {
class X86_64CompSimpMitigationPass : public MachineFunctionPass {
public:
  static char ID;

  X86_64CompSimpMitigationPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override;

  bool shouldRunOnMachineFunction(MachineFunction &MF);

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    MachineFunctionPass::getAnalysisUsage(AU);
    AU.setPreservesCFG();
  }

  StringRef getPassName() const override {
    return "computation simplication mitigations";
  }

private:
  void doX86CompSimpHardening(MachineInstr &MI, MachineBasicBlock &MBB,
                              MachineFunction &MF);
};
} // end anonymous namespace

void X86_64CompSimpMitigationPass::doX86CompSimpHardening(
    MachineInstr &MI, MachineBasicBlock &MBB, MachineFunction &MF) {

  DebugLoc DL = MI.getDebugLoc();
  const auto &STI = MF.getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF.getRegInfo();

  switch (MI.getOpcode()) {}
}

bool X86_64CompSimpMitigationPass::runOnMachineFunction(MachineFunction &MF) {
  if (!shouldRunOnMachineFunction(MF)) {
    return false; // Doesn't modify the func if not running
  }

  bool doesModifyFunction{false};

  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      // Don't harden frame setup stuff like `push rbp`
      if (MI.mayStore() && !MI.getFlag(MachineInstr::MIFlag::FrameSetup)) {
        doX86CompSimpHardening(MI, MBB, MF);
        doesModifyFunction = true; // Modifies the func if it does run
      }
    }
  }
  return doesModifyFunction;
}

// This will eventually check for the secret attribute. For now, just use
// function names.
bool X86_64CompSimpMitigationPass::shouldRunOnMachineFunction(
    MachineFunction &MF) {
  Function &F = MF.getFunction();

  for (auto &Arg : F.args()) {
    if (Arg.hasAttribute(Attribute::Secret)) {
      return true;
    }
  }
  return false;
}

char X86_64CompSimpMitigationPass::ID = 0;

FunctionPass *llvm::createX86_64CompSimpMitigationPass() {
  return new X86_64CompSimpMitigationPass();
}

INITIALIZE_PASS(X86_64CompSimpMitigationPass, "csimp-mitigation",
                "Mitigations for computation simplication optimizations", true,
                true)

