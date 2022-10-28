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

#include "cmath"
#include "llvm/Pass.h"

// TODO: replace all the following uses with the new def

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
  void doX86CompSimpHardening(MachineInstr *MI);
  void subFallBack(MachineInstr *MI);
  void insertSafeSub32Before(MachineInstr *MI);
};
} // end anonymous namespace

void X86_64CompSimpMitigationPass::insertSafeSub32Before(MachineInstr *MI) {
  /**
   *  subl ecx eax
   *
   *    ↓
   *
   *  subl eax, 2^31
   *  subl eax, 2^31
   *  setz r11b
   *  subq r11, 2^32 - 1
   *  subq r11, 1
   *  subq rax, r11
   *  subq rcx, rax
   *  subq rcx, r11
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand Op1 = MI->getOperand(1);
  MachineOperand Op2 = MI->getOperand(2);

  assert(Op1.isReg() && "Op1 is a reg");
  assert(Op2.isReg() && "Op2 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32ri), Op2.getReg())
      .addReg(Op2.getReg())
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32ri), Op2.getReg())
      .addReg(Op2.getReg())
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R11B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R11)
      .addReg(X86::R11)
      .addImm(pow(2, 32) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R11)
      .addReg(X86::R11)
      .addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2.getReg())
      .addReg(Op2.getReg())
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::subFallBack(MachineInstr *MI) {
  /**
   *  subl ecx eax
   *
   *    ↓
   *
   *  subl eax, 2^31 ;; this and next 2 insns are safe test for zero
   *  subl eax, 2^31
   *  setz r11b ;; doesn't affect flags, but sets r11b
   *  cmovz r13d, eax ;; save eax
   *  cmovz r12d, ecx ;; save ecx
   *  cmovz eax, r11d ;; load into eax 1 if eax was originally zero, or do
   * nothing if it was non-zero subl ecx, eax ;; if eax originally 0, then
   * this is blinding on r11d, else if eax non-zero, then it's the real
   * subtraction subl r11, 2^31 ;; this and next 2 insns are safe test for
   * zero (in this case, r11b = 1 if eax = 0, so test for non-zero really)
   *  subl r11, 2^31
   *  cmovnz ecx, r12d ;; just load ecx into ecx if eax was originally zero
   *  cmovnz eax, r13d ;; re-load saved eax since we clobbered it for blinding
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand Op1 = MI->getOperand(1);
  MachineOperand Op2 = MI->getOperand(2);

  assert(Op1.isReg() && "Op1 is a reg");
  assert(Op2.isReg() && "Op2 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32ri), Op2.getReg())
      .addReg(Op2.getReg())
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32ri), Op2.getReg())
      .addReg(Op2.getReg())
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R11B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(Op2.getReg())
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R9D)
      .addReg(X86::R9D)
      .addReg(Op1.getReg())
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2.getReg())
      .addReg(Op2.getReg())
      .addReg(X86::R11D)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32ri), X86::R11)
      .addReg(X86::R11)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32ri), X86::R11)
      .addReg(X86::R11)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(X86::R9D)
      .addImm(5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2.getReg())
      .addReg(Op2.getReg())
      .addReg(X86::R10D)
      .addImm(5);
  MI->eraseFromParent();
}

void X86_64CompSimpMitigationPass::doX86CompSimpHardening(MachineInstr *MI) {
  switch (MI->getOpcode()) {
  case X86::SUB32rm:
  case X86::SUB32rr: {
    insertSafeSub32Before(MI);
    MI->print(llvm::errs());
    llvm::errs() << "\n the above one <> \n";
    MI->eraseFromParent();
  }
  }
}

bool X86_64CompSimpMitigationPass::runOnMachineFunction(MachineFunction &MF) {
  llvm::errs() << "CS: Runing comp simp mitigation pass\n";
  // TODO: remove the short circuit for formal testing
  if (false && !shouldRunOnMachineFunction(MF)) {
    return false; // Doesn't modify the func if not running
  }
  bool doesModifyFunction{false};

  std::vector<MachineInstr *> Instructions;
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      // Don't harden frame setup stuff like `push rbp`
      if (!MI.mayLoadOrStore() &&
          !MI.getFlag(MachineInstr::MIFlag::FrameSetup)) {
        Instructions.push_back(&MI);
        doesModifyFunction = true; // Modifies the func if it does run
      }
    }
  }
  // if(Instructions.size() > 0) MF.print(llvm::errs());
  for (MachineInstr *MI : Instructions) {
    doX86CompSimpHardening(MI);
  }
  // if(Instructions.size() > 0) MF.print(llvm::errs());
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

