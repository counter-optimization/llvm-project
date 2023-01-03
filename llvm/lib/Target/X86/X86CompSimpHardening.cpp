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
  Register get64BitReg(MachineOperand *MO, const TargetRegisterInfo *TRI);
  void insertSafeOr32Before(MachineInstr *MI);
  void insertSafeAnd32Before(MachineInstr *MI);
  void insertSafeAnd64Before(MachineInstr *MI);
  void insertSafeSub32Before(MachineInstr *MI);
  void insertSafeAdd32Before(MachineInstr *MI);
};
} // end anonymous namespace

Register get64BitReg(MachineOperand *MO, const TargetRegisterInfo *TRI) {
}

void X86_64CompSimpMitigationPass::insertSafeOr32Before(MachineInstr *MI) {

  /**
   * or ecx, eax
   *
   *      ↓
   *
   * movq r10, rax
   * movl ecx, ecx
   * movl eax, eax
   * movq r11, 2^33
   * sub  rax, r11
   * sub  rcx, r11
   * or   rcx, rax
   * movl ecx, ecx
   * movq rax, r10
   *
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

  auto Op2_64 = TRI->getMatchingSuperReg(Op2.getReg(), X86::sub_32bit,
                                         &X86::GR64RegClass);
  auto Op1_64 = TRI->getMatchingSuperReg(Op1.getReg(), X86::sub_32bit,
                                         &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1.getReg())
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2.getReg())
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1.getReg())
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R10);
}
void X86_64CompSimpMitigationPass::insertSafeAnd64Before(MachineInstr *MI) {
  /**
   *	andq rcx, rax
   *
   *      ↓
   *
   *  movq r10 , 2^16
   *  movw r10w, cx
   *  movw cx  , 1^16
   *  movq r11 , 2^16
   *  movw r11w, ax
   *  movw ax  , 1^16
   *  and  rcx , rax
   *  and  r10 , r11
   *  movw cx  , r10w
   *  movw ax  , r11w
   *
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

  auto Op1_16 = TRI->getSubReg(Op1.getReg(), 4);
  auto Op2_16 = TRI->getSubReg(Op2.getReg(), 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAnd32Before(MachineInstr *MI) {
  /**
   *  andl ecx, eax
   *
   *    ↓
   *
   *  movq r10, rax ; save rax
   *  movl ecx, ecx ; zero top 32 bits of ecx
   *  movl eax, eax ; zero top 32 bits of eax
   *  movq r11, 2^33
   *  sub  rax, r11
   *  sub  rcx, r11
   *  and  rcx, rax
   *  movl ecx, ecx
   *  movq rax, r10
   *
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

  auto Op2_64 = TRI->getMatchingSuperReg(Op2.getReg(), X86::sub_32bit,
                                         &X86::GR64RegClass);
  auto Op1_64 = TRI->getMatchingSuperReg(Op1.getReg(), X86::sub_32bit,
                                         &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1.getReg())
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2.getReg())
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1.getReg())
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R10);
}

void X86_64CompSimpMitigationPass::insertSafeAdd32Before(MachineInstr *MI) {
  /**
   *  addl ecx eax
   *
   *    ↓
   *
   *  movq rdx, 2^32
   *  subq rax, rdx
   *  subq rcx, rdx
   *  addq rcx, rax
   *  movq rdx, -(2^33)
   *  subq rcx, rdx
   *
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 32));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2.getReg())
      .addReg(Op2.getReg())
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
      .addImm(-1 * pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(X86::R11);
}

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
  // TODO: do we care about these?
  // case X86::AND32ri:
  // case X86::AND32rm:
  case X86::AND32rr: {
    insertSafeAnd32Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::AND64rr: {
    insertSafeAnd64Before(MI);
    MI->eraseFromParent();
    break;                       
  }
  case X86::OR32rr: {
    insertSafeOr32Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::SUB32rm:
  case X86::SUB32rr: {
    // insertSafeSub32Before(MI);
    // MI->eraseFromParent();
    break;
  }
  case X86::ADD32rm:
  case X86::ADD32rr: {
    insertSafeAdd32Before(MI);
    MI->eraseFromParent();
    break;
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

