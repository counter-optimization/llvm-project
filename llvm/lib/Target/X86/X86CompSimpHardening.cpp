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

static cl::opt<bool>
    EnableCompSimp("x86-cs", cl::desc("Enable the X86 comp simp mitigation."),
                   cl::init(false));

static cl::opt<std::string> CompSimpCSVPath("x86-cs-csv-path",
                                            cl::desc("X86 comp simp csv path."),
                                            cl::init("test_alert.csv"));

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
  void insertSafeOr8Before(MachineInstr *MI);
  void insertSafeOr16Before(MachineInstr *MI);
  void insertSafeOr32Before(MachineInstr *MI);
  void insertSafeOr32ri8Before(MachineInstr *MI);
  void insertSafeOr64Before(MachineInstr *MI);
  void insertSafeOr64rmBefore(MachineInstr *MI);
  void insertSafeOr64ri8Before(MachineInstr *MI);
  void insertSafeXor8Before(MachineInstr *MI);
  void insertSafeXor8rmBefore(MachineInstr *MI);
  void insertSafeXor16Before(MachineInstr *MI);
  void insertSafeXor32Before(MachineInstr *MI);
  void insertSafeXor32rmBefore(MachineInstr *MI);
  void insertSafeXor32ri8Before(MachineInstr *MI);
  void insertSafeXor64Before(MachineInstr *MI);
  void insertSafeXor64rmBefore(MachineInstr *MI);
  void insertSafeXor64mrBefore(MachineInstr *MI);
  void insertSafeAnd8Before(MachineInstr *MI);
  void insertSafeTest8riBefore(MachineInstr *MI);
  void insertSafeTest8i8Before(MachineInstr *MI);
  void insertSafeTest8miBefore(MachineInstr *MI);
  void insertSafeShl8rClBefore(MachineInstr *MI);
  void insertSafeShr8riBefore(MachineInstr *MI);
  void insertSafeShr32rClBefore(MachineInstr *MI);
  void insertSafeShl32rClBefore(MachineInstr *MI);
  void insertSafeShl32riBefore(MachineInstr *MI);
  void insertSafeSar32r1Before(MachineInstr *MI);
  void insertSafeSar64riBefore(MachineInstr *MI);
  void insertSafeShl64riBefore(MachineInstr *MI);
  void insertSafeShr64riBefore(MachineInstr *MI);
  void insertSafeShr32riBefore(MachineInstr *MI);
  void insertSafeShr32r1Before(MachineInstr *MI);
  void insertSafeSar8r1Before(MachineInstr *MI);
  void insertSafeAnd16Before(MachineInstr *MI);
  void insertSafeAnd32Before(MachineInstr *MI);
  void insertSafeTest32Before(MachineInstr *MI);
  void insertSafeAnd32riBefore(MachineInstr *MI);
  void insertSafeAnd32ri8Before(MachineInstr *MI);
  void insertSafeAnd64Before(MachineInstr *MI);
  void insertSafeAnd64ri32Before(MachineInstr *MI);
  void insertSafeAnd64ri8Before(MachineInstr *MI);
  void insertSafeSub16Before(MachineInstr *MI);
  void insertSafeSub32Before(MachineInstr *MI);
  void insertSafeSub32OldBefore(MachineInstr *MI);
  void insertSafeSub64Before(MachineInstr *MI);
  void insertSafeSub64rmBefore(MachineInstr *MI);
  void insertSafeAdd16Before(MachineInstr *MI);
  void insertSafeAdd32Before(MachineInstr *MI);
  void insertSafeAdd32rmBefore(MachineInstr *MI);
  void insertSafeAdd32ri8Before(MachineInstr *MI);
  void insertSafeAdc32mi8Before(MachineInstr *MI);
  void insertSafeAdd32ri32Before(MachineInstr *MI);
  void insertSafeAdd32OldBefore(MachineInstr *MI);
  void insertSafeAdd64Before(MachineInstr *MI);
  void insertSafeAdd64rmBefore(MachineInstr *MI);
  void insertSafeAdd64mrBefore(MachineInstr *MI);
  void insertSafeAdc64mrBefore(MachineInstr *MI);
  void insertSafeAdd64ri8Before(MachineInstr *MI);
  void insertSafeAdc64ri8Before(MachineInstr *MI);
  void insertSafeAdd64ri32Before(MachineInstr *MI);
  void insertSafeAdd64mi32Before(MachineInstr *MI);
  void insertSafeAdd64mi8Before(MachineInstr *MI);
  void insertSafeShr64Before(MachineInstr *MI);
  void insertSafeShr32Before(MachineInstr *MI);
  void insertSafeAdc64Before(MachineInstr *MI);
  void insertSafeAdc64rmBefore(MachineInstr *MI);
  void insertSafeAdd64RR(MachineInstr *MI, MachineOperand *Op1,
                         MachineOperand *Op2);
};
} // end anonymous namespace

Register get64BitReg(MachineOperand *MO, const TargetRegisterInfo *TRI) {}

static Register getEqR12(Register EAX) {
  switch (EAX) {
  case X86::RAX:
    return X86::R12;
  case X86::EAX:
    return X86::R12D;
  case X86::AX:
    return X86::R12W;
  case X86::AH:
    return X86::R12BH;
  case X86::AL:
    return X86::R12B;
  default:
    return EAX;
  }
}

void X86_64CompSimpMitigationPass::insertSafeSar8r1Before(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getImm();

  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R11B)
      .addReg(Op1)
      .addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), Op1)
      .addReg(Op1)
      .addImm(pow(2, 5) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(56);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SAR64ri), Op1)
      .addReg(Op1)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(56);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op1_64).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeShr8riBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getImm();

  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R11B)
      .addReg(Op1)
      .add(MOp2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), Op1)
      .addReg(Op1)
      .addImm(pow(2, 5) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), Op1)
      .addReg(Op1)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op1_64).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeShr32r1Before(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).addImm(1);

  auto Op1 = X86::R13D;
  auto Op2 = MOp1.getReg();

  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);
  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(Op2)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), Op1)
      .addReg(Op1)
      .addImm(pow(2, 5) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64rCL), Op2_64).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2)
      .addReg(Op2)
      .addReg(X86::R10D)
      .addImm(5);
}

void X86_64CompSimpMitigationPass::insertSafeShr32riBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(2);
  MachineOperand MOp2 = MI->getOperand(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R13B).add(MOp1);

  auto Op1 = X86::R13B;
  auto Op2 = MOp2.getReg();

  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);
  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(Op2)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), Op2_64)
      .addReg(Op2_64)
      .addImm(MOp1.getImm() & 31);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2)
      .addReg(Op2)
      .addReg(X86::R10D)
      .addImm(5);
}

void X86_64CompSimpMitigationPass::insertSafeShl64riBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp1 = MI->getOperand(2);
  auto Op2 = MOp2.getReg();
  auto Op1 = MOp1.getImm();

  auto Op2_64 = Op2;
  auto Op2_16 = TRI->getSubReg(Op2_64, 4);
  if (Op1 == 0) {
    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64ri32), Op2_64)
        .addReg(Op2_64)
        .addImm(0x0);
    return;
  }
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10).addImm(0x80000000000000C0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Op2_64)
      .addReg(Op2_64)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R10);
}

void X86_64CompSimpMitigationPass::insertSafeShr64riBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp1 = MI->getOperand(2);
  auto Op2 = MOp2.getReg();
  auto Op1 = MOp1.getImm();

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op2_16 = TRI->getSubReg(Op2_64, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R13D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  if (Op1 == 0)
    Op1 = 1;
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::R13)
      .addReg(X86::R13)
      .addReg(Op2_64)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), Op2_64)
      .addReg(Op2_64)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64r1), X86::R10).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr),
  // Op2_64).addReg(Op2_64).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R10).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R13)
      .addImm(5);
}

void X86_64CompSimpMitigationPass::insertSafeSar64riBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp1 = MI->getOperand(2);
  auto Op2 = MOp2.getReg();
  auto Op1 = MOp1.getImm();

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op2_16 = TRI->getSubReg(Op2_64, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R13D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  if (Op1 == 0)
    Op1 = 1;
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::R13)
      .addReg(X86::R13)
      .addReg(Op2_64)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SAR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SAR64ri), Op2_64)
      .addReg(Op2_64)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64r1), X86::R10).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R10).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R13)
      .addImm(5);
}

void X86_64CompSimpMitigationPass::insertSafeSar32r1Before(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp2 = MI->getOperand(1);
  auto Op2 = MOp2.getReg();

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R10B).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(Op2)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op2_64)
      .addReg(Op2_64)
      .addImm(32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SAR64ri), Op2_64)
      .addReg(Op2_64)
      .addImm(1 & 31);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op2_64)
      .addReg(Op2_64)
      .addImm(32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2)
      .addReg(Op2)
      .addReg(X86::R10D)
      .addImm(5);
}

void X86_64CompSimpMitigationPass::insertSafeShl32riBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(2);
  MachineOperand MOp2 = MI->getOperand(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R13B).add(MOp1);

  auto Op1 = X86::R13B;
  auto Op2 = MOp2.getReg();

  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);
  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(Op2)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), Op1)
      .addReg(Op1)
      .addImm(pow(2, 5) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Op2_64)
      .addReg(Op2_64)
      .add(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2)
      .addReg(Op2)
      .addReg(X86::R10D)
      .addImm(5);
}

void X86_64CompSimpMitigationPass::insertSafeShl32rClBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);

  auto Op1 = X86::CL;
  auto Op2 = MOp1.getReg();

  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);
  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(Op2)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), Op1)
      .addReg(Op1)
      .addImm(pow(2, 5) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64rCL), Op2_64).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2)
      .addReg(Op2)
      .addReg(X86::R10D)
      .addImm(5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op1_64).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeShr32rClBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);

  auto Op1 = X86::CL;
  auto Op2 = MOp1.getReg();

  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);
  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(Op2)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), Op1)
      .addReg(Op1)
      .addImm(pow(2, 5) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64rCL), Op2_64).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2)
      .addReg(Op2)
      .addReg(X86::R10D)
      .addImm(5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op1_64).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeShl8rClBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::CL;

  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);
  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_8bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(32 - 5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(Op1_64)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), Op2)
      .addReg(Op2)
      .addImm(pow(2, 5) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64rCL), X86::R11).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2).addReg(X86::R11B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R10)
      .addImm(5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op1_64).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeTest8miBefore(MachineInstr *MI) {
  /**
   * and cl, al
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movb r10b, cl
   * movq r11, 2^16 (32-bit)
   * movb r11b, al
   * and r10, r11
   * movw cl, r10l
   * movw al, r11l
   *
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  // TODO is it index 1 or 0?
  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(MOp2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R14).add(MOp1);

  auto Op1 = X86::R14B;
  auto Op2 = X86::R13B;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::TEST64rr))
      .addReg(X86::R10)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1).addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2).addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeTest8i8Before(MachineInstr *MI) {
  /**
   * and cl, al
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movb r10b, cl
   * movq r11, 2^16 (32-bit)
   * movb r11b, al
   * and r10, r11
   * movw cl, r10l
   * movw al, r11l
   *
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  // TODO is it index 1 or 0?
  MachineOperand MOp2 = MI->getOperand(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(MOp2);

  auto Op1 = X86::AL;
  auto Op2 = X86::R13B;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::TEST64rr))
      .addReg(X86::R10)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1).addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2).addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeTest8riBefore(MachineInstr *MI) {
  /**
   * and cl, al
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movb r10b, cl
   * movq r11, 2^16 (32-bit)
   * movb r11b, al
   * and r10, r11
   * movw cl, r10l
   * movw al, r11l
   *
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13B;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::TEST64rr))
      .addReg(X86::R10)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1).addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2).addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeAnd8Before(MachineInstr *MI) {
  /**
   * and cl, al
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movb r10b, cl
   * movq r11, 2^16 (32-bit)
   * movb r11b, al
   * and r10, r11
   * movw cl, r10l
   * movw al, r11l
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R10).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1.getReg()).addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2.getReg()).addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeXor8rmBefore(MachineInstr *MI) {
  /**
   * xor cl, al
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movb r10b, cl
   * movq r11, 2^16 (32-bit)
   * movb r11b, al
   * xor r10, r11
   * movw cl, r10l
   * movw al, r11l
   *
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13B;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1).addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2).addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeXor8Before(MachineInstr *MI) {
  /**
   * xor cl, al
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movb r10b, cl
   * movq r11, 2^16 (32-bit)
   * movb r11b, al
   * xor r10, r11
   * movw cl, r10l
   * movw al, r11l
   *
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1).addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2).addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeOr8Before(MachineInstr *MI) {
  /**
   * or cl, al
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movb r10b, cl
   * movq r11, 2^16 (32-bit)
   * movb r11b, al
   * or r10, r11
   * movw cl, r10l
   * movw al, r11l
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R10).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1.getReg()).addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2.getReg()).addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeOr16Before(MachineInstr *MI) {
  /**
   * or cx, ax
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movw r10w, cx
   * movq r11, 2^16 (32-bit)
   * movw r11w, ax
   * or r10, r11
   * movw cx, r10w
   * movw ax, r11w
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R10).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1.getReg())
      .addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2.getReg())
      .addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAnd16Before(MachineInstr *MI) {
  /**
   * and cx, ax
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movw r10w, cx
   * movq r11, 2^16 (32-bit)
   * movw r11w, ax
   * and r10, r11
   * movw cx, r10w
   * movw ax, r11w
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R10).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1.getReg())
      .addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2.getReg())
      .addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeXor16Before(MachineInstr *MI) {
  /**
   * xor cx, ax
   *
   *      ↓
   *
   * movq r10, 2^16 (32-bit)
   * movw r10w, cx
   * movq r11, 2^16 (32-bit)
   * movw r11w, ax
   * xor r10, r11
   * movw cx, r10w
   * movw ax, r11w
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1.getReg())
      .addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2.getReg())
      .addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeXor64mrBefore(MachineInstr *MI) {
  /**
   * xor rcx, rax
   *
   *      ↓
   *
   * movq r10, 2^16 (32 bit)
   * movw r10w, cx
   * movw cx, 0xFFFF
   * movq r11, 2^16 (32 bit)
   * movw 11w, ax
   * movw ax, 0xFFFF
   * xor rcx, rax
   * xor r10, r11
   * movw cx, r10w
   * movw ax, r11w
   *
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp2.isReg() && "Op2 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp1);

  auto Op2 = MOp2.getReg();
  auto Op1 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R11W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr)).add(MOp1).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeXor64rmBefore(MachineInstr *MI) {
  /**
   * xor rcx, rax
   *
   *      ↓
   *
   * movq r10, 2^16 (32 bit)
   * movw r10w, cx
   * movw cx, 0xFFFF
   * movq r11, 2^16 (32 bit)
   * movw 11w, ax
   * movw ax, 0xFFFF
   * xor rcx, rax
   * xor r10, r11
   * movw cx, r10w
   * movw ax, r11w
   *
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeXor64Before(MachineInstr *MI) {
  /**
   * xor rcx, rax
   *
   *      ↓
   *
   * movq r10, 2^16 (32 bit)
   * movw r10w, cx
   * movw cx, 0xFFFF
   * movq r11, 2^16 (32 bit)
   * movw 11w, ax
   * movw ax, 0xFFFF
   * xor rcx, rax
   * xor r10, r11
   * movw cx, r10w
   * movw ax, r11w
   *
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeXor32ri8Before(MachineInstr *MI) {
  /**
   * xor ecx, eax
   *
   *      ↓
   *
   * movq r10, rax
   * movl ecx, ecx
   * movl eax, eax
   * movq r11, 2^33
   * sub  rax, r11
   * sub  rcx, r11
   * xor  rcx, rax
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R10);
}

void X86_64CompSimpMitigationPass::insertSafeXor32rmBefore(MachineInstr *MI) {
  /**
   * xor ecx, eax
   *
   *      ↓
   *
   * movq r10, rax
   * movl ecx, ecx
   * movl eax, eax
   * movq r11, 2^33
   * sub  rax, r11
   * sub  rcx, r11
   * xor  rcx, rax
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R10);
}

void X86_64CompSimpMitigationPass::insertSafeXor32Before(MachineInstr *MI) {
  /**
   * xor ecx, eax
   *
   *      ↓
   *
   * movq r10, rax
   * movl ecx, ecx
   * movl eax, eax
   * movq r11, 2^33
   * sub  rax, r11
   * sub  rcx, r11
   * xor  rcx, rax
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R10);
}

void X86_64CompSimpMitigationPass::insertSafeOr64ri8Before(MachineInstr *MI) {
  /**
   * or rcx, rax
   *
   *      ↓
   *
   * movq r10, 2^16 (32 bit)
   * movw r10w, cx
   * movw cx, 0xFFFF
   * movq r11, 2^16 (32 bit)
   * movw 11w, ax
   * movw ax, 0xFFFF
   * or rcx, rax
   * or r10, r11
   * movw cx, r10w
   * movw ax, r11w
   *
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R12).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R11W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R12W);
}

void X86_64CompSimpMitigationPass::insertSafeOr64rmBefore(MachineInstr *MI) {
  /**
   * or rcx, rax
   *
   *      ↓
   *
   * movq r10, 2^16 (32 bit)
   * movw r10w, cx
   * movw cx, 0xFFFF
   * movq r11, 2^16 (32 bit)
   * movw 11w, ax
   * movw ax, 0xFFFF
   * or rcx, rax
   * or r10, r11
   * movw cx, r10w
   * movw ax, r11w
   *
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R12).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R11W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R12W);
}

void X86_64CompSimpMitigationPass::insertSafeOr64Before(MachineInstr *MI) {
  /**
   * or rcx, rax
   *
   *      ↓
   *
   * movq r10, 2^16 (32 bit)
   * movw r10w, cx
   * movw cx, 0xFFFF
   * movq r11, 2^16 (32 bit)
   * movw 11w, ax
   * movw ax, 0xFFFF
   * or rcx, rax
   * or r10, r11
   * movw cx, r10w
   * movw ax, r11w
   *
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R12).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R11W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R12W);
}

void X86_64CompSimpMitigationPass::insertSafeOr32ri8Before(MachineInstr *MI) {

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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeTest32Before(MachineInstr *MI) {

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R12)
      .addReg(X86::R12)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R12)
      .addReg(X86::R12)
      .addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::TEST64rr)).addReg(Op1_64).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R12)
      .addReg(X86::R12)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R12)
      .addReg(X86::R12)
      .addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeAnd32riBefore(MachineInstr *MI) {
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R13D).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R12)
      .addReg(X86::R12)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R12)
      .addReg(X86::R12)
      .addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeAnd32ri8Before(MachineInstr *MI) {
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R13D).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R12)
      .addReg(X86::R12)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R12)
      .addReg(X86::R12)
      .addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeAdd32OldBefore(MachineInstr *MI) {
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

void X86_64CompSimpMitigationPass::insertSafeAnd64ri32Before(MachineInstr *MI) {
  /**
   *  andq rcx, rax
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R12).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R11W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R12W);
}

void X86_64CompSimpMitigationPass::insertSafeAnd64ri8Before(MachineInstr *MI) {
  /**
   *  andq rcx, rax
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R12).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R11W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R12W);
}

void X86_64CompSimpMitigationPass::insertSafeAnd64Before(MachineInstr *MI) {
  /**
   *  andq rcx, rax
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R12).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R11W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R12W);
}

void X86_64CompSimpMitigationPass::insertSafeShr32Before(MachineInstr *MI) {
  /**
   * shr eax
   *
   *    ↓
   *
   * movq r13, rcx
   * movl r10d, 2^31 (32-bit)
   * movb 10b, cl
   * shl r10, 27 (8-bit)
   * movq r12 0x0000000000000000
   * cmp r10d, 0x00 (8-bit)
   * setz r12b
   * cmovz r10d, eax
   * cmovz rcx, r12
   * movl eax, eax
   * movq r11, 2^63
   * sub rax, r11
   * and cl 2^5 - 1 (8-bit)
   * shr-cl rax
   * movl eax, eax
   * cmp r12d 0x00
   * cmovne eax, r10d
   * movq rcx, r13
   */
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand Op1 = MI->getOperand(1);
  auto Op1_64 = TRI->getMatchingSuperReg(Op1.getReg(), X86::sub_32bit,
                                         &X86::GR64RegClass);

  assert(Op1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(X86::RCX);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(X86::CL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(27);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12)
      .addImm(0x0000000000000000);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x00);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(Op1.getReg())
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::RCX)
      .addReg(X86::RCX)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1.getReg())
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), X86::CL)
      .addReg(X86::CL)
      .addImm(pow(2, 5) - 1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64rCL), X86::RAX).addReg(X86::RAX);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1.getReg())
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x00);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::EAX)
      .addReg(X86::EAX)
      .addReg(X86::R10D)
      .addImm(5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RCX).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeShr64Before(MachineInstr *MI) {
  /**
   * shr rax
   *
   *    ↓
   *
   * movq r14, rcx
   * movl r13d, 2^31 (32-bit)
   * movb r13b, cl
   * shl  r13, 24 (8-bit)
   * movq r12, 0x0 (64-bit)
   * cmpl r13d, 0x00 (8-bit)
   * setz r12b
   * cmovz r13, rax
   * cmovz rcx, r12
   * movq r10, 2^63 (64-bit)
   * movq r11, r10
   * movw r11w, ax
   * movw ax, 0XFFFF (16-bit)
   * shr-cl r11
   * shr-cl rax
   * shr-cl r10
   * shl-1  r10
   * sub rax, r10
   * add rax, r11
   * shr-1 r10
   * add rax, r10
   * cmp r12d 0x00 (8-bit)
   * cmovene rax, r13
   * movq rcx, r14
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand Op1 = MI->getOperand(1);

  assert(Op1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R14).addReg(X86::RCX);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R13D).addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R13B).addReg(X86::CL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R13)
      .addReg(X86::R13)
      .addImm(24);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R14)
      .addImm(0x0000000000000000);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R13D).addImm(0x00);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::R13)
      .addReg(X86::R13)
      .addReg(Op1.getReg())
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::RCX)
      .addReg(X86::RCX)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10).addImm(pow(2, 63));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(X86::AX);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::AX).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64rCL), X86::R11).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64rCL), Op1.getReg())
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64rCL), X86::R10).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R10).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R10).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x00);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(X86::R13)
      .addImm(5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RCX).addReg(X86::R14);
}

void X86_64CompSimpMitigationPass::insertSafeAdc64Before(MachineInstr *MI) {
  /**
   *  addq rcx rax
   *
   *    ↓
   *
   *  movq r10, 2^48
   *  movw r10w, cx
   *  movw cx, 0xFFFF
   *  movq r11, 2^48
   *  movw r11w, ax
   *  movw ax, 0xFFFF
   *  rol r10, 16
   *  rol r11, 16
   *  ror rcx, 16
   *  ror rax, 16
   *  adc r10d, r11d // CF + lower halves
   *  adc rcx, rax // CF + CF' + lower halves + upper halves
   *  ror r11, 16
   *  rol rax, 16
   *  ror r10, 16
   *  rcl rcx, 16
   *  movw cx, r10w
   *  movw ax, r11w
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

  auto Op2_8 = TRI->getSubReg(Op2.getReg(), 1);
  auto Op1_8 = TRI->getSubReg(Op1.getReg(), 1);

  auto Op1_16 = TRI->getSubReg(Op1.getReg(), 4);
  auto Op2_16 = TRI->getSubReg(Op2.getReg(), 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op1R = Op1.getReg();
  Register Op2R = Op2.getReg();
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op1R).addReg(Op1R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op2R).addReg(Op2R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC32rr), X86::R11D)
      .addReg(X86::R11D)
      .addReg(X86::R12D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op1.getReg())
      .addReg(Op1.getReg())
      .addReg(Op2.getReg());

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op2R).addReg(Op2R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op1R).addReg(Op1R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op2_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op1R).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op1R).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdc64rmBefore(MachineInstr *MI) {
  /**
   *  addq rcx, mem
   *
   *    ↓
   *
   *  movq r13, mem
   *  addq rcx, r13
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(Op2);

  auto Op3 = Op1.getReg();
  auto Op4 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op3).addReg(Op3).addReg(Op4);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdd64RR(MachineInstr *MI,
                                                     MachineOperand *MO1,
                                                     MachineOperand *MO2) {
  /**
   *  addq rcx rax
   *
   *    ↓
   *
   *  movq r10, 2^48
   *  movw r10w, cx
   *  movw cx, 0xFFFF
   *  movq r11, 2^48
   *  movw r11w, ax
   *  movw ax, 0xFFFF
   *  rol r10, 16
   *  rol r11, 16
   *  ror rcx, 16
   *  ror rax, 16
   *  add r10d, r11d
   *  adc rcx, rax
   *  ror r11, 16
   *  rol rax, 16
   *  ror r10, 16
   *  rcl rcx, 16
   *  movw cx, r10w
   *  movw ax, r11w
   */

  Register Op3 = X86::R13;
  if (MO1->isReg())
    Op3 = MO1->getReg();

  Register Op4 = X86::R14;
  if (MO2->isReg())
    Op4 = MO2->getReg();

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R11D)
      .addReg(X86::R11D)
      .addReg(X86::R12D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op4).addReg(Op4).addReg(Op3);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64rr), X86::R12).addReg(X86::R12);
  // if(KKcount == 1)
  // BuildMI(*MBB, *MI, DL, TII->get(X86::SYSEXIT));
}

void X86_64CompSimpMitigationPass::insertSafeAdd64mi8Before(MachineInstr *MI) {
  /**
   *  addq mem, imm32
   *
   *    ↓
   *
   *  movq r13, mem
   *  movq r14, imm32
   *  addq r13, r14
   *  movq mem, r13
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R14).add(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(Op1);

  auto Op3 = X86::R13;
  auto Op4 = X86::R14;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R11D)
      .addReg(X86::R11D)
      .addReg(X86::R12D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op4).addReg(Op4).addReg(Op3);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdd64mi32Before(MachineInstr *MI) {
  /**
   *  addq mem, imm32
   *
   *    ↓
   *
   *  movq r13, mem
   *  movq r14, imm32
   *  addq r13, r14
   *  movq mem, r13
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R14).add(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(Op1);

  auto Op3 = X86::R13;
  auto Op4 = X86::R14;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R11D)
      .addReg(X86::R11D)
      .addReg(X86::R12D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op4).addReg(Op4).addReg(Op3);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdd64ri32Before(MachineInstr *MI) {
  /**
   *  addq rcx, imm32
   *
   *    ↓
   *
   *  movq r13, imm32
   *  addq rcx, r13
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R13).add(Op2);

  auto Op3 = Op1.getReg();
  auto Op4 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op3).addReg(Op3).addReg(Op4);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdc64ri8Before(MachineInstr *MI) {
  /**
   *  addq rcx, imm8
   *
   *    ↓
   *
   *  movq r13, imm8
   *  addq rcx, r13
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(Op2);

  auto Op3 = Op1.getReg();
  auto Op4 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op3).addReg(Op3).addReg(Op4);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdd64ri8Before(MachineInstr *MI) {
  /**
   *  addq rcx, imm8
   *
   *    ↓
   *
   *  movq r13, imm8
   *  addq rcx, r13
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(Op2);

  auto Op3 = Op1.getReg();
  auto Op4 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op3).addReg(Op3).addReg(Op4);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdc64mrBefore(MachineInstr *MI) {
  /**
   *  addq mem, rax
   *
   *    ↓
   *
   *  movq r13, mem
   *  addq r13, rax
   *  movq mem, r13
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

  assert(Op2.isReg() && "Op2 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(Op1);

  auto Op4 = Op2.getReg();
  auto Op3 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op3).addReg(Op3).addReg(Op4);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr)).add(Op1).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeAdd64mrBefore(MachineInstr *MI) {
  /**
   *  addq mem, rax
   *
   *    ↓
   *
   *  movq r13, mem
   *  addq r13, rax
   *  movq mem, r13
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

  assert(Op2.isReg() && "Op2 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(Op1);

  auto Op4 = Op2.getReg();
  auto Op3 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op3).addReg(Op3).addReg(Op4);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr)).add(Op1).addReg(X86::R13);
}

void X86_64CompSimpMitigationPass::insertSafeAdd64rmBefore(MachineInstr *MI) {
  /**
   *  addq rcx, mem
   *
   *    ↓
   *
   *  movq r13, mem
   *  addq rcx, r13
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(Op2);

  auto Op3 = Op1.getReg();
  auto Op4 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op3).addReg(Op3).addReg(Op4);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdd64Before(MachineInstr *MI) {

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op3 = MOp1.getReg();
  auto Op4 = MOp2.getReg();

  auto Op4_8 = TRI->getSubReg(MOp2.getReg(), 1);
  auto Op3_8 = TRI->getSubReg(MOp1.getReg(), 1);
  auto Op4_16 = TRI->getSubReg(MOp2.getReg(), 4);
  auto Op3_16 = TRI->getSubReg(MOp1.getReg(), 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op4R = Op4;
  Register Op3R = Op3;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op3).addReg(Op3).addReg(Op4);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op3R).addReg(Op3R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op4R).addReg(Op4R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeSub64rmBefore(MachineInstr *MI) {
  /**
   *  subq rcx rax
   *
   *    ↓
   *  movq r10, 2^48
   *  movw r10w, cx
   *  movw cx, 0xFFFF
   *  movq r11, 2^48
   *  movw r11w, ax
   *  movw ax, 0xFFFF
   *  rol r10, 16
   *  rol r11, 16
   *  ror rcx, 16
   *  ror rax, 16
   *  sub r10d, r11d
   *  sbb rcx, rax
   *  ror r10, 16
   *  ror r11, 16
   *  rol rcx, 16
   *  rol rax, 16
   *  movw cx, r10w
   *  movw ax, r11w
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2);

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op1).addReg(Op1).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op2).addReg(Op2).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SBB64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op1).addReg(Op1).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op2).addReg(Op2).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeSub64Before(MachineInstr *MI) {
  /**
   *  subq rcx rax
   *
   *    ↓
   *  movq r10, 2^48
   *  movw r10w, cx
   *  movw cx, 0xFFFF
   *  movq r11, 2^48
   *  movw r11w, ax
   *  movw ax, 0xFFFF
   *  rol r10, 16
   *  rol r11, 16
   *  ror rcx, 16
   *  ror rax, 16
   *  sub r10d, r11d
   *  sbb rcx, rax
   *  ror r10, 16
   *  ror r11, 16
   *  rol rcx, 16
   *  rol rax, 16
   *  movw cx, r10w
   *  movw ax, r11w
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");
  assert(MOp2.isReg() && "Op2 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = MOp2.getReg();

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op1).addReg(Op1).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op2).addReg(Op2).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SBB64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op1).addReg(Op1).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op2).addReg(Op2).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R11W);
}

void X86_64CompSimpMitigationPass::insertSafeAdd32ri32Before(MachineInstr *MI) {
  /**
   * add ecx, mem
   *
   *    ↓
   *
   * movl r13d, mem
   * movq r11, r13
   * movl r13d, r13d
   * sub  r13, 2^31 (32-bit)
   * sub  r13, 2^31 (32-bit)
   * add  rcx, r13
   * movl ecx, ecx
   * movq r13, r11
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R13).add(Op2);
  auto R1 = Op1.getReg();
  auto R2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(R2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(R1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R2).addReg(R2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeAdd32ri8Before(MachineInstr *MI) {
  /**
   * add ecx, mem
   *
   *    ↓
   *
   * movl r13d, mem
   * movq r11, r13
   * movl r13d, r13d
   * sub  r13, 2^31 (32-bit)
   * sub  r13, 2^31 (32-bit)
   * add  rcx, r13
   * movl ecx, ecx
   * movq r13, r11
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R13).add(Op2);
  auto R1 = Op1.getReg();
  auto R2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(R2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(R1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R2).addReg(R2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeAdc32mi8Before(MachineInstr *MI) {
  /**
   * add ecx, mem
   *
   *    ↓
   *
   * movl r13d, mem
   * movq r11, r13
   * movl r13d, r13d
   * sub  r13, 2^31 (32-bit)
   * sub  r13, 2^31 (32-bit)
   * add  rcx, r13
   * movl ecx, ecx
   * movq r13, r11
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R13).add(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R14).add(Op1);

  auto R1 = X86::R14D;
  auto R2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(R2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(R1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R2).addReg(R2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeAdd32rmBefore(MachineInstr *MI) {
  /**
   * add ecx, mem
   *
   *    ↓
   *
   * movl r13d, mem
   * movq r11, r13
   * movl r13d, r13d
   * sub  r13, 2^31 (32-bit)
   * sub  r13, 2^31 (32-bit)
   * add  rcx, r13
   * movl ecx, ecx
   * movq r13, r11
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rm), X86::R13).add(Op2);

  auto R1 = Op1.getReg();
  auto R2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(R2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(R1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R2).addReg(R2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeAdd32Before(MachineInstr *MI) {
  /**
   * add ecx, eax
   *
   *    ↓
   *
   * movq r11, rax
   * movl eax, eax
   * sub  rax, 2^31 (32-bit)
   * sub  rax, 2^31 (32-bit)
   * add  rcx, rax
   * movl ecx, ecx
   * movq rax, r11
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

  auto R1 = Op1.getReg();
  auto R2 = Op2.getReg();

  auto Op2_64 =
      TRI->getMatchingSuperReg(R2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(R1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R2).addReg(R2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeAdd16Before(MachineInstr *MI) {
  /**
   * sub cx, ax
   *
   *
   * movq r11, rax
   * movq r10, rcx
   * movl eax, eax
   * sub  rax, 2^31 (32-bit)
   * sub  rax, 2^31 (32-bit)
   * sub  r10, rax
   * movw cx,  r10w
   * movq rax, r11
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

  auto Op2_32 = TRI->getSubReg(Op2_64, 6);
  auto I =
      BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10W).addReg(Op2_64);
  I->dump();
  assert(false && "TODO: debug this to find how to convert cx into ecx");
}

void X86_64CompSimpMitigationPass::insertSafeSub16Before(MachineInstr *MI) {
  /**
   * sub cx, ax
   *
   *
   * movq r11, rax
   * movq r10, rcx
   * movl eax, eax
   * sub  rax, 2^31 (32-bit)
   * sub  rax, 2^31 (32-bit)
   * sub  r10, rax
   * movw cx,  r10w
   * movq rax, r11
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

  auto Op2_32 = TRI->getSubReg(Op2_64, 6);
  auto I =
      BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10W).addReg(Op2_64);
  I->dump();
  assert(false && "TODO: debug this to find how to convert cx into ecx");
}

void X86_64CompSimpMitigationPass::insertSafeSub32Before(MachineInstr *MI) {
  /**
   * sub ecx, eax
   *
   *    ↓
   *
   * movq r11, rax
   * movl eax, eax
   * sub  rax, 2^31 (32-bit)
   * sub  rax, 2^31 (32-bit)
   * sub  rcx, rax
   * movl ecx, ecx
   * movq rax, r11
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2.getReg())
      .addReg(Op2.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1.getReg())
      .addReg(Op1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeSub32OldBefore(MachineInstr *MI) {
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R12D)
      .addReg(X86::R12D)
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
      .addReg(X86::R12D)
      .addImm(5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2.getReg())
      .addReg(Op2.getReg())
      .addReg(X86::R10D)
      .addImm(5);
  MI->eraseFromParent();
}

void X86_64CompSimpMitigationPass::doX86CompSimpHardening(MachineInstr *MI) {
  switch (MI->getOpcode()) {
  // case X86::ADD64ri8: {
  //    insertSafeAdd64ri8Before(MI);
  //    MI->eraseFromParent();
  //    break;
  // }
  case X86::ADD64ri32: {
     insertSafeAdd64ri32Before(MI);
     MI->eraseFromParent();
     break;
  }
  case X86::ADD64mi32: {
     insertSafeAdd64mi32Before(MI);
     MI->eraseFromParent();
     break;
  }
  case X86::ADD64mi8: {
     insertSafeAdd64mi8Before(MI);
     MI->eraseFromParent();
     break;
  }
  case X86::ADD64mr: {
    insertSafeAdd64mrBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD64rm: {
    insertSafeAdd64rmBefore(MI);
    MI->eraseFromParent();
    break;
  }
  // case X86::ADD64rr: {
  //   insertSafeAdd64Before(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::ADC64rr: {
  //   insertSafeAdc64Before(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::ADC64rm: {
    insertSafeAdc64rmBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::ADC64mr: {
    insertSafeAdc64mrBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::ADC64ri8: {
    insertSafeAdc64ri8Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD32rr: {
      insertSafeAdd32Before(MI);
      MI->eraseFromParent();
      break;
  }
  case X86::ADD32rm: {
      insertSafeAdd32rmBefore(MI);
      MI->eraseFromParent();
      break;
  }
  case X86::ADD32ri8: {
      insertSafeAdd32ri8Before(MI);
      MI->eraseFromParent();
      break;
  }
  case X86::ADD32i32: {
      MI->dump();
      assert(false && "comp simp todo");
      break;
  }
  case X86::ADC32mi8: {
      insertSafeAdc32mi8Before(MI);
      MI->eraseFromParent();
      break;
  }
  case X86::ADD8rm: {
      MI->dump();
      assert(false && "comp simp todo");
      break;
  }
  case X86::AND64rr: {
    insertSafeAnd64Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::AND64i32: {
    assert(false && "comp simp todo");
    break;
  }
  case X86::AND64ri32: {
    insertSafeAnd64ri32Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::AND64ri8: {
    insertSafeAnd64ri8Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::AND32rr: {
      insertSafeAnd32Before(MI);
      MI->eraseFromParent();
      break;
  }
  case X86::AND32ri8: {
      insertSafeAnd32ri8Before(MI);
      MI->eraseFromParent();
      break;
  }
  case X86::AND32ri: {
      insertSafeAnd32riBefore(MI);
      MI->eraseFromParent();
      break;
  }
  case X86::AND32i32: {
      assert(false && "comp simp todo");
      insertSafeAnd32riBefore(MI);
      MI->eraseFromParent();
      break;
  }
  case X86::OR64rr: {
    insertSafeOr64Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::OR64rm: {
    insertSafeOr64rmBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::OR64ri8: {
    insertSafeOr64ri8Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::OR32rr: {
    insertSafeOr32Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::OR32ri8: {
    insertSafeOr32ri8Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::OR8rm: {
    assert(false && "comp simp todo");
    break;
  }
  case X86::MUL64m: {
    assert(false && "comp simp todo");
    break;
  }
  case X86::IMUL32rm: {
    assert(false && "comp simp todo");
    break;
  }
  case X86::XOR64rr: {
    insertSafeXor64Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR64rm: {
    insertSafeXor64rmBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR64mr: {
    insertSafeXor64mrBefore(MI);
    MI->eraseFromParent();
    break;
  }
  // case X86::XOR32rr: {
  //   insertSafeXor32Before(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::XOR32rm: {
    insertSafeXor32rmBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR32ri8: {
    insertSafeXor32ri8Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR8rr: {
    insertSafeXor8Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR8rm: {
    insertSafeXor8rmBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::SUB64rr: {
    insertSafeSub64Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::SUB64rm: {
    insertSafeSub64rmBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::SUB32rr: {
    insertSafeSub32Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::TEST32rr: {
    insertSafeTest32Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::AND8rr: {
    insertSafeAnd8Before(MI);
    MI->eraseFromParent();
    break;
  }
  // case X86::TEST8ri: {
  //   insertSafeTest8riBefore(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::TEST8i8: {
    insertSafeTest8i8Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::TEST8mi: {
    insertSafeTest8miBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::SHL8rCL: {
    insertSafeShl8rClBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::SHR8ri: {
    insertSafeShr8riBefore(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::SAR8r1: {
    insertSafeSar8r1Before(MI);
    MI->eraseFromParent();
    break;
  }
  // case X86::SHR32rCL: {
  //   insertSafeShr32rClBefore(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::SHR32ri: {
  //   insertSafeShr32riBefore(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::SHR32r1: {
    insertSafeShr32r1Before(MI);
    MI->eraseFromParent();
    break;
  }
  case X86::SHL32rCL: {
    insertSafeShl32rClBefore(MI);
    MI->eraseFromParent();
    break;
  }
  // case X86::SHL32ri: {
  //   insertSafeShl32riBefore(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::SAR32r1: {
    insertSafeSar32r1Before(MI);
    MI->eraseFromParent();
    break;
  }
  // case X86::SAR64ri: {
  //   insertSafeSar64riBefore(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::SHR64ri: {
  //   insertSafeShr64riBefore(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::SHL64ri: {
  //   insertSafeShl64riBefore(MI);
  //   MI->eraseFromParent();
  //   break;
  // }

  /*
    case X86::AND16rr: {
  insertSafeAnd16Before(MI);
  MI->eraseFromParent();
  break;
  }

  case X86::OR8rr: {
  insertSafeOr8Before(MI);
  MI->eraseFromParent();
  break;
  }
  case X86::OR16rr: {
  insertSafeOr16Before(MI);
  MI->eraseFromParent();
  break;
  }
        case X86::XOR16rr: {
  insertSafeXor16Before(MI);
  MI->eraseFromParent();
  break;
  }
        case X86::SUB8rr: {
  // TODO: not present in libNa to debug
  assert(false && "support sub8");
  break;
  }
  case X86::SUB16rr: {
  // TODO: not present in libNa to debug
  insertSafeSub16Before(MI);
  MI->eraseFromParent();
  break;
  }
  // case X86::SUB32rm:
      case X86::ADD8rr: {
  // TODO: not present in libNa to debug
  assert(false && "support sub8");
  break;
  }
  case X86::ADD16rr: {
  insertSafeAdd16Before(MI);
  MI->eraseFromParent();
  break;
  }
  // case X86::ADD32rm:
    // case X86::SHR64rCL: {
  //   break;
  //   // TODO: 10 failures
  //   insertSafeShr64Before(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::SHR32rCL: {
  //   // TODO: 27 failures
  //   insertSafeShr32Before(MI);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::SHR16rCL: {
  assert(false && "support shr16cl");
  }
  case X86::SHR8rCL: {
  assert(false && "support shr8cl");
  }
  */
  }
}

bool X86_64CompSimpMitigationPass::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableCompSimp)
    return false;
  llvm::errs() << "[CompSimp]\n";
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

