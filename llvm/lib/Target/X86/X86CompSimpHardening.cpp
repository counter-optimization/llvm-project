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
#include "llvm/Support/CommandLine.h"

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
static cl::opt<bool> EnableCompSimpDynStat(
    "x86-cs-dyn-stat",
    cl::desc("Enable the X86 comp simp dynamic instrumentation count."),
    cl::init(false));

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
  void insertSafeSbb32Before(MachineInstr *MI);
  void insertSafeSub8rrBefore(MachineInstr *MI);
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
  void insertSafeMul32rBefore(MachineInstr *MI);
  void insertSafeIMul32rrBefore(MachineInstr *MI);
  void insertSafeIMul32rmBefore(MachineInstr *MI);
  void insertSafeCmp64rrBefore(MachineInstr *MI);
  void insertSafeCmp32rrBefore(MachineInstr *MI);
  void insertSafeCmp32mrBefore(MachineInstr *MI);
  void insertSafeCmp32rmBefore(MachineInstr *MI);
  void insertSafeCmp64rmBefore(MachineInstr *MI);
  void insertSafeCmp8rrBefore(MachineInstr *MI);
  void insertSafeVPXorrrBefore(MachineInstr *MI);
  void insertSafeVPOrrrBefore(MachineInstr *MI);
  void insertSafeVPOrrmBefore(MachineInstr *MI);
  void insertSafeVPAddDrrBefore(MachineInstr *MI);
  void insertSafeVPAddQrrBefore(MachineInstr *MI);
  void insertSafeVPAddQYrrBefore(MachineInstr *MI);
  void insertSafeVPAddQYrmBefore(MachineInstr *MI);
  void insertSafeVPAddQrmBefore(MachineInstr *MI);
  void insertSafeVPAddDYrrBefore(MachineInstr *MI);
  void insertSafeVPAddDYrmBefore(MachineInstr *MI);
  void insertSafeVPAddDrmBefore(MachineInstr *MI);
  void insertSafeVPOryrrBefore(MachineInstr *MI);
  void insertSafeVPXoryrrBefore(MachineInstr *MI);
  void insertSafeVPXoryrmBefore(MachineInstr *MI);
  void insertSafeVPXorrmBefore(MachineInstr *MI);
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

static void callUpdateStats(MachineInstr *MI, int Idx) {
  // TODO:fix test case failures
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  Module *M = MI->getMF()->getFunction().getParent();
  GlobalValue *Scratch = M->getNamedValue("updateStats");
  const uint32_t *RegMask = TRI->getCallPreservedMask(*MF, CallingConv::C);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(X86::RDI);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(X86::RSP);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::SSP);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::EDI).addImm(Idx);
  auto LoadAddr = BuildMI(*MBB, *MI, DL, TII->get(X86::CALL64pcrel32))
                      .addGlobalAddress(Scratch, 0, X86II::MO_PLT)
                      .addRegMask(RegMask);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::SSP).addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RSP).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RDI).addReg(X86::R10);

  LoadAddr->dump();
}

static void updateStats(MachineInstr *MI, int Idx) {
  if (!EnableCompSimpDynStat)
    return;
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  Module *M = MI->getMF()->getFunction().getParent();
  GlobalValue *Scratch = M->getNamedValue("llvm_stats");
  auto LoadAddr = BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R10)
                      .addReg(X86::RIP)
                      .addImm(1)
                      .addReg(0)
                      .addGlobalAddress(Scratch, 0, X86II::MO_GOTPCREL)
                      .addReg(0);
  auto Load = BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rm), X86::R13D)
                  .addReg(X86::R10)
                  .addImm(1)
                  .addReg(0)
                  .addImm(4 * Idx)
                  .addReg(0);
  auto Inc = BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32ri), X86::R13D)
                 .addReg(X86::R13D)
                 .addImm(1);
  auto Store = BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32mr))
                   .addReg(X86::R10)
                   .addImm(1)
                   .addReg(0)
                   .addImm(4 * Idx)
                   .addReg(0)
                   .addReg(X86::R13D);
}

void X86_64CompSimpMitigationPass::insertSafeVPXorrmBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();

  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArm), X86::XMM12)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  auto MOp2 = X86::XMM12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Set all bits in xmm to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM13);

  // Interchange upper and lower halves of XMM15/14 and XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM13)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM13)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORrr), X86::XMM13)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Set all bits in XMM15/14 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM15);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM14);

  // Interchange upper and lower halves of input registers and XMM15/14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(MOp1)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(MOp2)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Build result by interchanging upper and lower halves of XMM13 and XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15)
      .addImm(0x0F);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPXoryrmBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();

  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrm), X86::YMM12)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  auto MOp2 = X86::YMM12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Set all bits in ymm to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM13);

  // Interchange upper and lower halves of YMM15/14 and YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM13)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM13)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORYrr), X86::YMM13)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Set all bits in XMM15/14 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM15);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM14);

  // Interchange upper and lower halves of input registers and XMM15/14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(MOp1)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(MOp2)
      .addImm(0x0F);

  // XOR YMM15 with YMM14 and save the result in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Build result by interchanging upper and lower halves of YMM13 and YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM15)
      .addImm(0x0F);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPXoryrrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();
  auto MOp2 = MI->getOperand(2).getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Set all bits in ymm to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM13);

  // Interchange upper and lower halves of YMM15/14 and YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM13)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM13)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORYrr), X86::YMM13)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Set all bits in XMM15/14 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM15);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM14);

  // Interchange upper and lower halves of input registers and XMM15/14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(MOp1)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(MOp2)
      .addImm(0x0F);

  // XOR YMM15 with YMM14 and save the result in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Build result by interchanging upper and lower halves of YMM13 and YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM15)
      .addImm(0x0F);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPOryrrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();
  auto MOp2 = MI->getOperand(2).getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Set all bits in xmm to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM13);

  // Interchange upper and lower halves of YMM15/14 and YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM13)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM13)
      .addImm(0x0F);

  // XOR YMM15 with YMM14 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM13)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Set all bits in YMM15/14 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM15);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM14);

  // Interchange upper and lower halves of input registers and YMM15/14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(MOp1)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(MOp2)
      .addImm(0x0F);

  // XOR YMM15 with YMM14 and save the result in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Build result by interchanging upper and lower halves of YMM13 and YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWYrri), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM15)
      .addImm(0x0F);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPOrrmBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();

  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArm), X86::XMM12)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  auto MOp2 = X86::XMM12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Set all bits in xmm to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM13);

  // Interchange upper and lower halves of XMM15/14 and XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM13)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM13)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM13)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Set all bits in XMM15/14 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM15);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM14);

  // Interchange upper and lower halves of input registers and XMM15/14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(MOp1)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(MOp2)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Build result by interchanging upper and lower halves of XMM13 and XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15)
      .addImm(0x0F);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPOrrrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();
  auto MOp2 = MI->getOperand(2).getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Set all bits in xmm to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM13);

  // Interchange upper and lower halves of XMM15/14 and XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM13)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM13)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM13)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Set all bits in XMM15/14 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM15);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM14);

  // Interchange upper and lower halves of input registers and XMM15/14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(MOp1)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(MOp2)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Build result by interchanging upper and lower halves of XMM13 and XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15)
      .addImm(0x0F);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAddDrmBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();

  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArm), X86::XMM12)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  auto MOp2 = X86::XMM12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Shift left XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(16);

  // Shift left XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(16);

  // Shift right XMM15 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(1);

  // Shift right XMM14 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(1);

  // Set all bits in XMM13 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM13);

  // Shift right XMM13 by 31 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(31);

  // OR XMM15 with XMM13 and save the result in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM13);

  // OR XMM14 with XMM13 and save the result in XMM14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM13);

  // ADD XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDrr), X86::XMM13)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Shift XMM13 right by 15 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(15);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Shift right XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(16);

  // Shift left XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(16);

  // Shift right XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(16);

  // Shift left XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(16);

  // Add XMM15 with XMM13 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15);

  // Add XMM14 with XMM13 and save the result in X86::XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM14);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAddDYrmBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();

  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrm), X86::YMM12)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  auto MOp2 = X86::YMM12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Shift left YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(16);

  // Shift left YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(16);

  // Shift right YMM15 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(1);

  // Shift right YMM14 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(1);

  // Set all bits in YMM13 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM13);

  // Shift right YMM13 by 31 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM13)
      .addReg(X86::YMM13)
      .addImm(31);

  // OR YMM15 with YMM13 and save the result in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM13);

  // OR YMM14 with YMM13 and save the result in YMM14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM13);

  // ADD YMM15 with YMM14 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDYrr), X86::YMM13)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Shift YMM13 right by 15 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM13)
      .addReg(X86::YMM13)
      .addImm(15);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Shift right YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(16);

  // Shift left YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(16);

  // Shift right YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(16);

  // Shift left YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(16);

  // Add YMM15 with YMM13 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM15);

  // Add YMM14 with YMM13 and save the result in X86::YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM14);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAddDYrrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();
  auto MOp2 = MI->getOperand(2).getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Shift left YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(16);

  // Shift left YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(16);

  // Shift right YMM15 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(1);

  // Shift right YMM14 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(1);

  // Set all bits in YMM13 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM13);

  // Shift right YMM13 by 31 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM13)
      .addReg(X86::YMM13)
      .addImm(31);

  // OR YMM15 with YMM13 and save the result in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM13);

  // OR YMM14 with YMM13 and save the result in YMM14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM13);

  // ADD YMM15 with YMM14 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDYrr), X86::YMM13)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Shift YMM13 right by 15 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM13)
      .addReg(X86::YMM13)
      .addImm(15);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Shift right YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(16);

  // Shift left YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(16);

  // Shift right YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(16);

  // Shift left YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(16);

  // Add YMM15 with YMM13 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM15);

  // Add YMM14 with YMM13 and save the result in X86::YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM14);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAddDrrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();
  auto MOp2 = MI->getOperand(2).getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Shift left XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(16);

  // Shift left XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(16);

  // Shift right XMM15 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(1);

  // Shift right XMM14 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(1);

  // Set all bits in XMM13 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM13);

  // Shift right XMM13 by 31 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(31);

  // OR XMM15 with XMM13 and save the result in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM13);

  // OR XMM14 with XMM13 and save the result in XMM14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM13);

  // ADD XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDrr), X86::XMM13)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Shift XMM13 right by 15 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(15);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Shift right XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(16);

  // Shift left XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(16);

  // Shift right XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLDri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(16);

  // Shift left XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(16);

  // Add XMM15 with XMM13 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15);

  // Add XMM14 with XMM13 and save the result in X86::XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDDrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM14);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAddQrmBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();

  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArm), X86::XMM12)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  auto MOp2 = X86::XMM12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Shift left XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(32);

  // Shift left XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(32);

  // Shift right XMM15 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(1);

  // Shift right XMM14 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(1);

  // Set all bits in XMM13 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM13);

  // Shift right XMM13 by 31 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(61);

  // OR XMM15 with XMM13 and save the result in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM13);

  // OR XMM14 with XMM13 and save the result in XMM14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM13);

  // ADD XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQrr), X86::XMM13)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Shift XMM13 right by 15 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(31);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Shift right XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(32);

  // Shift left XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(32);

  // Shift right XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(32);

  // Shift left XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(32);

  // Add XMM15 with XMM13 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15);

  // Add XMM14 with XMM13 and save the result in X86::XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM14);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAddQYrrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();
  auto MOp2 = MI->getOperand(2).getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Shift left YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(32);

  // Shift left YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(32);

  // Shift right YMM15 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(1);

  // Shift right YMM14 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(1);

  // Set all bits in YMM13 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM13);

  // Shift right YMM13 by 31 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM13)
      .addReg(X86::YMM13)
      .addImm(61);

  // OR YMM15 with YMM13 and save the result in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM13);

  // OR YMM14 with YMM13 and save the result in YMM14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM13);

  // ADD YMM15 with YMM14 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQYrr), X86::YMM13)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Shift YMM13 right by 15 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM13)
      .addReg(X86::YMM13)
      .addImm(31);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Shift right YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(32);

  // Shift left YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(32);

  // Shift right YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(32);

  // Shift left YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(32);

  // Add YMM15 with YMM13 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM15);

  // Add YMM14 with YMM13 and save the result in X86::YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM14);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAddQYrmBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();

  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrm), X86::XMM12)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  auto MOp2 = X86::YMM12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Shift left YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(32);

  // Shift left YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(32);

  // Shift right YMM15 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(1);

  // Shift right YMM14 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(1);

  // Set all bits in YMM13 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM13);

  // Shift right YMM13 by 31 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM13)
      .addReg(X86::YMM13)
      .addImm(61);

  // OR YMM15 with YMM13 and save the result in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM13);

  // OR YMM14 with YMM13 and save the result in YMM14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM14)
      .addReg(X86::YMM14)
      .addReg(X86::YMM13);

  // ADD YMM15 with YMM14 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQYrr), X86::YMM13)
      .addReg(X86::YMM15)
      .addReg(X86::YMM14);

  // Shift YMM13 right by 15 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM13)
      .addReg(X86::YMM13)
      .addImm(31);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM14).addReg(MOp2);

  // Shift right YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(32);

  // Shift left YMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQYri), X86::YMM15)
      .addReg(X86::YMM15)
      .addImm(32);

  // Shift right YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(32);

  // Shift left YMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQYri), X86::YMM14)
      .addReg(X86::YMM14)
      .addImm(32);

  // Add YMM15 with YMM13 and save the result in YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM15);

  // Add YMM14 with YMM13 and save the result in X86::YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQYrr), X86::YMM13)
      .addReg(X86::YMM13)
      .addReg(X86::YMM14);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAddQrrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();
  auto MOp2 = MI->getOperand(2).getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Shift left XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(32);

  // Shift left XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(32);

  // Shift right XMM15 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(1);

  // Shift right XMM14 by 1 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(1);

  // Set all bits in XMM13 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM13);

  // Shift right XMM13 by 31 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(61);

  // OR XMM15 with XMM13 and save the result in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM13);

  // OR XMM14 with XMM13 and save the result in XMM14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM13);

  // ADD XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQrr), X86::XMM13)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Shift XMM13 right by 15 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(31);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Shift right XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(32);

  // Shift left XMM15 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQri), X86::XMM15)
      .addReg(X86::XMM15)
      .addImm(32);

  // Shift right XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSRLQri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(32);

  // Shift left XMM14 by 16 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLQri), X86::XMM14)
      .addReg(X86::XMM14)
      .addImm(32);

  // Add XMM15 with XMM13 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15);

  // Add XMM14 with XMM13 and save the result in X86::XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPADDQrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM14);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPXorrrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto MOp0 = MI->getOperand(0).getReg();
  auto MOp1 = MI->getOperand(1).getReg();
  auto MOp2 = MI->getOperand(2).getReg();

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).addReg(MOp1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), X86::XMM14).addReg(MOp2);

  // Set all bits in xmm to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM13);

  // Interchange upper and lower halves of XMM15/14 and XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM13)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM13)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORrr), X86::XMM13)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Set all bits in XMM15/14 to 1
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM15);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQBrr), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(X86::XMM14);

  // Interchange upper and lower halves of input registers and XMM15/14
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(MOp1)
      .addImm(0x0F);
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM14)
      .addReg(X86::XMM14)
      .addReg(MOp2)
      .addImm(0x0F);

  // XOR XMM15 with XMM14 and save the result in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Build result by interchanging upper and lower halves of XMM13 and XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15)
      .addImm(0x0F);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
      .addImm(0x80000000000000C0);
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

  // TODO fix the mem operand
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
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

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
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

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
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

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
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

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

void X86_64CompSimpMitigationPass::insertSafeIMul32rmBefore(MachineInstr *MI) {
   MachineBasicBlock *MBB = MI->getParent();
   MachineFunction *MF = MBB->getParent();
   DebugLoc DL = MI->getDebugLoc();
   const auto &STI = MF->getSubtarget();
   auto *TII = STI.getInstrInfo();
   auto *TRI = STI.getRegisterInfo();
   auto &MRI = MF->getRegInfo();

   MachineOperand &MOp1 = MI->getOperand(1);
   MachineOperand &MOp2 = MI->getOperand(2);
   MachineOperand &MOp3 = MI->getOperand(3);
   MachineOperand &MOp4 = MI->getOperand(4);
   MachineOperand &MOp5 = MI->getOperand(5);
   MachineOperand &MOp6 = MI->getOperand(6);

   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R12).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

   Register ECX = X86::R12D;
   Register RCX = X86::R12;

   /*
    mov64 rdx  (expt 2 63)
    mov32 r10d ecx
    sub64 r10 rdx
    mov32 r11d eax
    sub64 r11 rdx
    mov64 rax r11
    mul64 r10
    shl64 r10 63
    mov8 r10b 1
    shl64 r11 63
    mov8 r11b 1
    mov8 dl al
    mov8 al 2
    sub64 rax r10
    sub64 rax r11
    mov8 al dl
    mov64 rdx rax
    mov16 dx 1 (16-bit)
    shr64 rdx 32
    mov32 eax eax

    mul32 ecx => mul32 eax ecx
   */

   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::RDX).addImm(pow(2, 63));
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10D).addReg(ECX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R10)
       .addReg(X86::R10)
       .addReg(ECX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R11D).addReg(X86::EAX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
       .addReg(X86::R11)
       .addReg(X86::RDX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R11);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r)).addReg(X86::R10);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
       .addReg(X86::R10)
       .addImm(63);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R10B).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R11)
       .addReg(X86::R11)
       .addImm(63);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R11B).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::DL).addReg(X86::AL);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL).addImm(2);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::RAX)
       .addReg(X86::RAX)
       .addReg(X86::R10);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::RAX)
       .addReg(X86::RAX)
       .addReg(X86::R11);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL).addReg(X86::DL);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RDX).addReg(X86::RAX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::DX).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::RDX)
       .addReg(X86::RDX)
       .addImm(32);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::EAX).addReg(X86::EAX);
}

void X86_64CompSimpMitigationPass::insertSafeIMul32rrBefore(MachineInstr *MI) {
   MachineBasicBlock *MBB = MI->getParent();
   MachineFunction *MF = MBB->getParent();
   DebugLoc DL = MI->getDebugLoc();
   const auto &STI = MF->getSubtarget();
   auto *TII = STI.getInstrInfo();
   auto *TRI = STI.getRegisterInfo();
   auto &MRI = MF->getRegInfo();

   MachineOperand &MOp1 = MI->getOperand(1);
   Register ECX = MI->getOperand(2).getReg();
   Register RCX =
       TRI->getMatchingSuperReg(ECX, X86::sub_32bit, &X86::GR64RegClass);

   /*
    mov64 rdx  (expt 2 63)
    mov32 r10d ecx
    sub64 r10 rdx
    mov32 r11d eax
    sub64 r11 rdx
    mov64 rax r11
    mul64 r10
    shl64 r10 63
    mov8 r10b 1
    shl64 r11 63
    mov8 r11b 1
    mov8 dl al
    mov8 al 2
    sub64 rax r10
    sub64 rax r11
    mov8 al dl
    mov64 rdx rax
    mov16 dx 1 (16-bit)
    shr64 rdx 32
    mov32 eax eax

    mul32 ecx => mul32 eax ecx
   */

   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::RDX).addImm(pow(2, 63));
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10D).addReg(ECX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R10)
       .addReg(X86::R10)
       .addReg(ECX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R11D).addReg(X86::EAX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
       .addReg(X86::R11)
       .addReg(X86::RDX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R11);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r)).addReg(X86::R10);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
       .addReg(X86::R10)
       .addImm(63);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R10B).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R11)
       .addReg(X86::R11)
       .addImm(63);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R11B).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::DL).addReg(X86::AL);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL).addImm(2);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::RAX)
       .addReg(X86::RAX)
       .addReg(X86::R10);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::RAX)
       .addReg(X86::RAX)
       .addReg(X86::R11);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL).addReg(X86::DL);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RDX).addReg(X86::RAX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::DX).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::RDX)
       .addReg(X86::RDX)
       .addImm(32);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::EAX).addReg(X86::EAX);
}

 void X86_64CompSimpMitigationPass::insertSafeMul32rBefore(MachineInstr *MI) {
   MachineBasicBlock *MBB = MI->getParent();
   MachineFunction *MF = MBB->getParent();
   DebugLoc DL = MI->getDebugLoc();
   const auto &STI = MF->getSubtarget();
   auto *TII = STI.getInstrInfo();
   auto *TRI = STI.getRegisterInfo();
   auto &MRI = MF->getRegInfo();

   MachineOperand &MOp1 = MI->getOperand(1);
   Register ECX = MOp1.getReg();
   Register RCX =
       TRI->getMatchingSuperReg(ECX, X86::sub_32bit, &X86::GR64RegClass);

   /*
    mov64 rdx  (expt 2 63)
    mov32 r10d ecx
    sub64 r10 rdx
    mov32 r11d eax
    sub64 r11 rdx
    mov64 rax r11
    mul64 r10
    shl64 r10 63
    mov8 r10b 1
    shl64 r11 63
    mov8 r11b 1
    mov8 dl al
    mov8 al 2
    sub64 rax r10
    sub64 rax r11
    mov8 al dl
    mov64 rdx rax
    mov16 dx 1 (16-bit)
    shr64 rdx 32
    mov32 eax eax

    mul32 ecx => mul32 eax ecx
   */

   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::RDX).addImm(pow(2, 63));
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10D).addReg(ECX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R10)
       .addReg(X86::R10)
       .addReg(ECX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R11D).addReg(X86::EAX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
       .addReg(X86::R11)
       .addReg(X86::RDX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R11);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r)).addReg(X86::R10);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
       .addReg(X86::R10)
       .addImm(63);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R10B).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R11)
       .addReg(X86::R11)
       .addImm(63);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R11B).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::DL).addReg(X86::AL);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL).addImm(2);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::RAX)
       .addReg(X86::RAX)
       .addReg(X86::R10);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::RAX)
       .addReg(X86::RAX)
       .addReg(X86::R11);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL).addReg(X86::DL);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RDX).addReg(X86::RAX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::DX).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::RDX)
       .addReg(X86::RDX)
       .addImm(32);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::EAX).addReg(X86::EAX);
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R14).add(MOp6);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5);

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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp6.isReg() && "Op6 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5);

  auto Op4 = MOp6.getReg();
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr)).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5).addReg(X86::R13);
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp6.isReg() && "Op6 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5);

  auto Op4 = MOp6.getReg();
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr)).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5).addReg(X86::R13);
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
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  assert(Op1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(Op2).add(Op3).add(Op4).add(Op5).add(Op6);

  auto Op7 = Op1.getReg();
  auto Op8 = X86::R13;

  auto Op8_8 = TRI->getSubReg(Op8, 1);
  auto Op7_8 = TRI->getSubReg(Op7, 1);

  auto Op8_16 = TRI->getSubReg(Op8, 4);
  auto Op7_16 = TRI->getSubReg(Op7, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op8_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op8_16).addImm(0xFFFF);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op7_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op7_16).addImm(0xFFFF);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);

  Register Op8R = Op8;
  Register Op7R = Op7;
  // if (Op1R == X86::RAX)
  //     Op1R = X86::R12;
  // if (Op2R == X86::RAX)
  //     Op2R = X86::R12;

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op8R).addReg(Op8R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Op7R).addReg(Op7R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R12D)
      .addReg(X86::R12D)
      .addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Op7).addReg(Op7).addReg(Op8);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RAX);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
      .addReg(X86::R12)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op7R).addReg(Op7R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op8R).addReg(Op8R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op7_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op8_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op7).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op8).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op8_16).addReg(X86::R11W);
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
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

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

void X86_64CompSimpMitigationPass::insertSafeCmp32mrBefore(MachineInstr *MI) {

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp3 = MI->getOperand(2);
  MachineOperand MOp4 = MI->getOperand(3);
  MachineOperand MOp5 = MI->getOperand(4);
  MachineOperand MOp6 = MI->getOperand(5);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(MOp6.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R12).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5);

  auto Op1 = X86::R12D;
  auto Op2 = X86::R10D;

  auto Op2_64 = TRI->getMatchingSuperReg(Op2, X86::sub_32bit,
                                         &X86::GR64RegClass);
  auto Op1_64 = TRI->getMatchingSuperReg(Op1, X86::sub_32bit,
                                         &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2)
      .addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1)
      .addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeCmp32rmBefore(MachineInstr *MI) {

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp3 = MI->getOperand(2);
  MachineOperand MOp4 = MI->getOperand(3);
  MachineOperand MOp5 = MI->getOperand(4);
  MachineOperand MOp6 = MI->getOperand(5);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(MOp1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R12).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

  auto Op1 = X86::R10D;
  auto Op2 = X86::R12D;

  auto Op2_64 = TRI->getMatchingSuperReg(Op2, X86::sub_32bit,
                                         &X86::GR64RegClass);
  auto Op1_64 = TRI->getMatchingSuperReg(Op1, X86::sub_32bit,
                                         &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2)
      .addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1)
      .addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}


void X86_64CompSimpMitigationPass::insertSafeCmp64rmBefore(MachineInstr *MI) {
  /**
   *  cmp rcx [ptr]
   *
   *    ↓
   *
   *  movq r12, rcx
   *  movq r10, 2^48
   *  movw r10w, r12w
   *  movw r12w, 0xFFFF
   *  movq r11, 2^48
   *  movw r11w, ax
   *  movw ax, 0xFFFF
   *  rol r10, 16
   *  rol r11, 16
   *  ror r12, 16
   *  ror rax, 16
   *  sub r10d, r11d
   *  sbb r12, rax
   *  ror r10, 16
   *  ror r11, 16
   *  rol r12, 16
   *  rol rax, 16
   *  movw r12w, r10w
   *  movw ax, r11w
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
  MachineOperand MOp3 = MI->getOperand(2);
  MachineOperand MOp4 = MI->getOperand(3);
  MachineOperand MOp5 = MI->getOperand(4);
  MachineOperand MOp6 = MI->getOperand(5);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(MOp1.getReg());
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

  auto Op1 = X86::R12;
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

void X86_64CompSimpMitigationPass::insertSafeCmp64rrBefore(MachineInstr *MI) {
  /**
   *  cmp rcx rax
   *
   *    ↓
   *
   *  movq r12, rcx
   *  movq r10, 2^48
   *  movw r10w, r12w
   *  movw r12w, 0xFFFF
   *  movq r11, 2^48
   *  movw r11w, ax
   *  movw ax, 0xFFFF
   *  rol r10, 16
   *  rol r11, 16
   *  ror r12, 16
   *  ror rax, 16
   *  sub r10d, r11d
   *  sbb r12, rax
   *  ror r10, 16
   *  ror r11, 16
   *  rol r12, 16
   *  rol rax, 16
   *  movw r12w, r10w
   *  movw ax, r11w
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
  assert(MOp2.isReg() && "Op2 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(MOp1.getReg());

  auto Op1 = X86::R12;
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rm), X86::R13).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

  auto R1 = MOp1.getReg();
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

void X86_64CompSimpMitigationPass::insertSafeCmp8rrBefore(MachineInstr *MI) {
  /*
   * sub cl, al
   *
   *   ↓
   *
   * movq r11, rax  
   * movq r10, rcx
   * movl eax, eax
   * sub  rax, 2^31 (32-bit)
   * sub  rax, 2^31 (32-bit)
   * sub  r10, rax
   * movb cl, r10b
   * movq rax, r11
   */ 

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(MI->getOperand(1).getReg());

  auto Op1 = X86::R12B;
  auto Op2 = MI->getOperand(2).getReg();

  auto Op2_64 = TRI->getMatchingSuperReg(Op2, X86::sub_8bit,
                                         &X86::GR64RegClass);
  auto Op1_64 = TRI->getMatchingSuperReg(Op1, X86::sub_8bit,
                                         &X86::GR64RegClass);

  auto Op2_32 = TRI->getSubReg(Op2_64, 6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2_32)
      .addReg(Op2_32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1)
      .addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeCmp32rrBefore(MachineInstr *MI) {
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(MI->getOperand(0).getReg());

  auto Op1 = X86::R10D;
  auto Op2 = MI->getOperand(1).getReg();

  auto Op2_64 = TRI->getMatchingSuperReg(Op2, X86::sub_32bit,
                                         &X86::GR64RegClass);
  auto Op1_64 = TRI->getMatchingSuperReg(Op1, X86::sub_32bit,
                                         &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2)
      .addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1)
      .addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeSub8rrBefore(MachineInstr *MI) {
  /*
   * sub cl, al
   *
   *   ↓
   *
   * movq r11, rax  
   * movq r10, rcx
   * movl eax, eax
   * sub  rax, 2^31 (32-bit)
   * sub  rax, 2^31 (32-bit)
   * sub  r10, rax
   * movb cl, r10b
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2_32)
      .addReg(Op2_32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
      .addReg(Op2_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1.getReg())
      .addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2_64).addReg(X86::R11);
}

void X86_64CompSimpMitigationPass::insertSafeSbb32Before(MachineInstr *MI) {
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
  //    updateStats(MI, 1); MI->eraseFromParent();
  //    break;
  // }
  // case X86::ADD64ri32: {
  //   insertSafeAdd64ri32Before(MI);
  //   updateStats(MI, 2);
  //   // callUpdateStats(MI, 5) ;
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::ADD64mi32: {
    insertSafeAdd64mi32Before(MI);
    updateStats(MI, 3);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD64mi8: {
    insertSafeAdd64mi8Before(MI);
    updateStats(MI, 4);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD64mr: {
    insertSafeAdd64mrBefore(MI);
    updateStats(MI, 5);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD64rm: {
    insertSafeAdd64rmBefore(MI);
    updateStats(MI, 6);
    MI->eraseFromParent();
    break;
  }
  // case X86::ADD64rr: {
  //   insertSafeAdd64Before(MI);
  //   updateStats(MI, 7); MI->eraseFromParent();
  //   break;
  // }
  // case X86::ADC64rr: {
  //   insertSafeAdc64Before(MI);
  //   updateStats(MI, 8); MI->eraseFromParent();
  //   break;
  // }
  case X86::ADC64rm: {
    insertSafeAdc64rmBefore(MI);
    updateStats(MI, 9);
    MI->eraseFromParent();
    break;
  }
  case X86::ADC64mr: {
    insertSafeAdc64mrBefore(MI);
    updateStats(MI, 10);
    MI->eraseFromParent();
    break;
  }
  case X86::ADC64ri8: {
    insertSafeAdc64ri8Before(MI);
    updateStats(MI, 11);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD32rr: {
    insertSafeAdd32Before(MI);
    updateStats(MI, 12);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD32rm: {
    insertSafeAdd32rmBefore(MI);
    updateStats(MI, 13);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD32ri8: {
    insertSafeAdd32ri8Before(MI);
    updateStats(MI, 14);
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
    updateStats(MI, 16);
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
    updateStats(MI, 18);
    MI->eraseFromParent();
    break;
  }
  case X86::AND64i32: {
    assert(false && "comp simp todo");
    break;
  }
  case X86::AND64ri32: {
    insertSafeAnd64ri32Before(MI);
    updateStats(MI, 20);
    MI->eraseFromParent();
    break;
  }
  case X86::AND64ri8: {
    insertSafeAnd64ri8Before(MI);
    updateStats(MI, 21);
    MI->eraseFromParent();
    break;
  }
  case X86::AND32rr: {
    insertSafeAnd32Before(MI);
    updateStats(MI, 22);
    MI->eraseFromParent();
    break;
  }
  case X86::AND32ri8: {
    insertSafeAnd32ri8Before(MI);
    updateStats(MI, 23);
    MI->eraseFromParent();
    break;
  }
  case X86::AND32ri: {
    insertSafeAnd32riBefore(MI);
    updateStats(MI, 24);
    MI->eraseFromParent();
    break;
  }
  case X86::AND32i32: {
    assert(false && "comp simp todo");
    insertSafeAnd32riBefore(MI);
    updateStats(MI, 25);
    MI->eraseFromParent();
    break;
  }
  case X86::OR64rr: {
    insertSafeOr64Before(MI);
    updateStats(MI, 26);
    MI->eraseFromParent();
    break;
  }
  case X86::OR64rm: {
    insertSafeOr64rmBefore(MI);
    updateStats(MI, 27);
    MI->eraseFromParent();
    break;
  }
  case X86::OR64ri8: {
    insertSafeOr64ri8Before(MI);
    updateStats(MI, 28);
    MI->eraseFromParent();
    break;
  }
  case X86::OR32rr: {
    insertSafeOr32Before(MI);
    updateStats(MI, 29);
    MI->eraseFromParent();
    break;
  }
  case X86::OR32ri8: {
    insertSafeOr32ri8Before(MI);
    updateStats(MI, 30);
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
  case X86::XOR64rr: {
    insertSafeXor64Before(MI);
    updateStats(MI, 34);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR64rm: {
    insertSafeXor64rmBefore(MI);
    updateStats(MI, 35);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR64mr: {
    insertSafeXor64mrBefore(MI);
    updateStats(MI, 36);
    MI->eraseFromParent();
    break;
  }
  // case X86::XOR32rr: {
  //   insertSafeXor32Before(MI);
  //   updateStats(MI, 37); MI->eraseFromParent();
  //   break;
  // }
  case X86::XOR32rm: {
    insertSafeXor32rmBefore(MI);
    updateStats(MI, 38);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR32ri8: {
    insertSafeXor32ri8Before(MI);
    updateStats(MI, 39);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR8rr: {
    insertSafeXor8Before(MI);
    updateStats(MI, 40);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR8rm: {
    insertSafeXor8rmBefore(MI);
    updateStats(MI, 41);
    MI->eraseFromParent();
    break;
  }
  case X86::SUB64rr: {
    insertSafeSub64Before(MI);
    updateStats(MI, 42);
    MI->eraseFromParent();
    break;
  }
  case X86::SUB64rm: {
    insertSafeSub64rmBefore(MI);
    updateStats(MI, 43);
    MI->eraseFromParent();
    break;
  }
  case X86::SUB32rr: {
    insertSafeSub32Before(MI);
    updateStats(MI, 44);
    MI->eraseFromParent();
    break;
  }
  case X86::TEST32rr: {
    insertSafeTest32Before(MI);
    updateStats(MI, 45);
    MI->eraseFromParent();
    break;
  }
  case X86::AND8rr: {
    insertSafeAnd8Before(MI);
    updateStats(MI, 46);
    MI->eraseFromParent();
    break;
  }
  // case X86::TEST8ri: {
  //   insertSafeTest8riBefore(MI);
  //   updateStats(MI, 47); MI->eraseFromParent();
  //   break;
  // }
  case X86::TEST8i8: {
    insertSafeTest8i8Before(MI);
    updateStats(MI, 48);
    MI->eraseFromParent();
    break;
  }
  case X86::TEST8mi: {
    insertSafeTest8miBefore(MI);
    updateStats(MI, 49);
    MI->eraseFromParent();
    break;
  }
  case X86::SHL8rCL: {
    insertSafeShl8rClBefore(MI);
    updateStats(MI, 50);
    MI->eraseFromParent();
    break;
  }
  case X86::SHR8ri: {
    insertSafeShr8riBefore(MI);
    updateStats(MI, 51);
    MI->eraseFromParent();
    break;
  }
  case X86::SAR8r1: {
    insertSafeSar8r1Before(MI);
    updateStats(MI, 52);
    MI->eraseFromParent();
    break;
  }
  // case X86::SHR32rCL: {
  //   insertSafeShr32rClBefore(MI);
  //   updateStats(MI, 53); MI->eraseFromParent();
  //   break;
  // }
  // case X86::SHR32ri: {
  //   insertSafeShr32riBefore(MI);
  //   updateStats(MI, 54); MI->eraseFromParent();
  //   break;
  // }
  case X86::SHR32r1: {
    insertSafeShr32r1Before(MI);
    updateStats(MI, 55);
    MI->eraseFromParent();
    break;
  }
  case X86::SHL32rCL: {
    insertSafeShl32rClBefore(MI);
    updateStats(MI, 56);
    MI->eraseFromParent();
    break;
  }
  // case X86::SHL32ri: {
  //   insertSafeShl32riBefore(MI);
  //   updateStats(MI, 57); MI->eraseFromParent();
  //   break;
  // }
  case X86::SAR32r1: {
    insertSafeSar32r1Before(MI);
    updateStats(MI, 58);
    MI->eraseFromParent();
    break;
  }
    // case X86::SAR64ri: {
    //   insertSafeSar64riBefore(MI);
    //   updateStats(MI, 59); MI->eraseFromParent();
    //   break;
    // }
    // case X86::SHR64ri: {
    //   insertSafeShr64riBefore(MI);
    //   updateStats(MI, 60); MI->eraseFromParent();
    //   break;
    // }
    // case X86::SHL64ri: {
    //   insertSafeShl64riBefore(MI);
    //   updateStats(MI, 61); MI->eraseFromParent();
    //   break;
    // }

    /*
      case X86::AND16rr: {
    insertSafeAnd16Before(MI);
    updateStats(MI, 62); MI->eraseFromParent();
    break;
    }

    case X86::OR8rr: {
    insertSafeOr8Before(MI);
    updateStats(MI, 63); MI->eraseFromParent();
    break;
    }
    case X86::OR16rr: {
    insertSafeOr16Before(MI);
    updateStats(MI, 64); MI->eraseFromParent();
    break;
    }
          case X86::XOR16rr: {
    insertSafeXor16Before(MI);
    updateStats(MI, 65); MI->eraseFromParent();
    break;
    }
    
    case X86::SUB16rr: {
    // TODO: not present in libNa to debug
    insertSafeSub16Before(MI);
    updateStats(MI, 67); MI->eraseFromParent();
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
    updateStats(MI, 70); MI->eraseFromParent();
    break;
    }
    // case X86::ADD32rm:
      // case X86::SHR64rCL: {
    //   break;
    //   // TODO: 10 failures
    //   insertSafeShr64Before(MI);
    //   updateStats(MI, 72); MI->eraseFromParent();
    //   break;
    // }
    // case X86::SHR32rCL: {
    //   // TODO: 27 failures
    //   insertSafeShr32Before(MI);
    //   updateStats(MI, 73); MI->eraseFromParent();
    //   break;
    // }
    case X86::SHR16rCL: {
    assert(false && "support shr16cl");
    updateStats(MI, 74); MI->eraseFromParent();
    }
    case X86::SHR8rCL: {
    assert(false && "support shr8cl");
    updateStats(MI, 75); MI->eraseFromParent();
    }
    */
  case X86::MUL32r: {
    insertSafeMul32rBefore(MI);
    updateStats(MI, 76);
    MI->eraseFromParent();
    break;
  }
  // case X86::CMP64rr: {
  //   insertSafeCmp64rrBefore(MI);
  //   updateStats(MI, 77);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::CMP64rm: {
  //   insertSafeCmp64rmBefore(MI);
  //   updateStats(MI, 78);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::CMP32rr: {
  //   insertSafeCmp32rrBefore(MI);
  //   updateStats(MI, 79);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::CMP32rm: {
  //   insertSafeCmp32rmBefore(MI);
  //   updateStats(MI, 80);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::CMP32mr: {
  //   insertSafeCmp32mrBefore(MI);
  //   updateStats(MI, 81);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::SUB8rr: {
    insertSafeSub8rrBefore(MI);
    updateStats(MI, 66); 
    MI->eraseFromParent();
    break;
  }
  case X86::CMP8rr: {
    insertSafeCmp8rrBefore(MI);
    updateStats(MI, 82);
    MI->eraseFromParent();
    break;
  }
  case X86::SBB32rr: {
    insertSafeSbb32Before(MI);
    updateStats(MI, 83);
    MI->eraseFromParent();
    break;
  }
  // case X86::IMUL32rr: {
  //   insertSafeIMul32rrBefore(MI);
  //   updateStats(MI, 84);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::IMUL32rm: {
  //   insertSafeIMul32rmBefore(MI);
  //   updateStats(MI, 85);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::VPXORrr: {
    insertSafeVPXorrrBefore(MI);
    updateStats(MI, 86);
    MI->eraseFromParent();
    break;
  }
  case X86::VPXORrm: {
    insertSafeVPXorrmBefore(MI);
    updateStats(MI, 87);
    MI->eraseFromParent();
    break;
  }
  case X86::VPXORYrr: {
    insertSafeVPXoryrrBefore(MI);
    updateStats(MI, 88);
    MI->eraseFromParent();
    break;
  }
  case X86::VPXORYrm: {
    insertSafeVPXoryrmBefore(MI);
    updateStats(MI, 89);
    MI->eraseFromParent();
    break;
  }
  case X86::PXORrr: {
    insertSafeVPXorrrBefore(MI);
    updateStats(MI, 90);
    MI->eraseFromParent();
    break;
  }
  case X86::PXORrm: {
    insertSafeVPXorrmBefore(MI);
    updateStats(MI, 91);
    MI->eraseFromParent();
    break;
  }
  case X86::VPORrr: {
    insertSafeVPOrrrBefore(MI);
    updateStats(MI, 92);
    MI->eraseFromParent();
    break;
  }
  case X86::VPORYrr: {
    insertSafeVPOryrrBefore(MI);
    updateStats(MI, 93);
    MI->eraseFromParent();
    break;
  }
  case X86::PORrr: {
    insertSafeVPOrrrBefore(MI);
    updateStats(MI, 94);
    MI->eraseFromParent();
    break;
  }
  case X86::PORrm: {
    insertSafeVPOrrmBefore(MI);
    updateStats(MI, 95);
    MI->eraseFromParent();
    break;
  }
  case X86::VPADDDrr: {
    insertSafeVPAddDrrBefore(MI);
    updateStats(MI, 96);
    MI->eraseFromParent();
    break;
  }
  case X86::VPADDDrm: {
    insertSafeVPAddDrmBefore(MI);
    updateStats(MI, 97);
    MI->eraseFromParent();
    break;
  }
  case X86::VPADDDYrr: {
    insertSafeVPAddDYrrBefore(MI);
    updateStats(MI, 98);
    MI->eraseFromParent();
    break;
  }
  case X86::VPADDDYrm: {
    insertSafeVPAddDYrmBefore(MI);
    updateStats(MI, 99);
    MI->eraseFromParent();
    break;
  }
  case X86::VPADDQrr: {
    insertSafeVPAddQrrBefore(MI);
    updateStats(MI, 100);
    MI->eraseFromParent();
    break;
  }
  case X86::VPADDQrm: {
    insertSafeVPAddQrmBefore(MI);
    updateStats(MI, 101);
    MI->eraseFromParent();
    break;
  }
  case X86::VPADDQYrr: {
    insertSafeVPAddQYrrBefore(MI);
    updateStats(MI, 102);
    MI->eraseFromParent();
    break;
  }
  case X86::VPADDQYrm: {
    insertSafeVPAddQYrmBefore(MI);
    updateStats(MI, 103);
    MI->eraseFromParent();
    break;
  }
  case X86::PADDQrr: {
    insertSafeVPAddQrrBefore(MI);
    updateStats(MI, 104);
    MI->eraseFromParent();
    break;
  }
  case X86::PADDQrm: {
    insertSafeVPAddQrmBefore(MI);
    updateStats(MI, 105);
    MI->eraseFromParent();
    break;
  }
}
}

static void setupTest(MachineFunction &MF) {
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      if (MI.getOpcode() == X86::RET64) {
        MachineBasicBlock *MBB = MI.getParent();
        MachineFunction *MF = MBB->getParent();
        DebugLoc DL = MI.getDebugLoc();
        const auto &STI = MF->getSubtarget();
        auto *TII = STI.getInstrInfo();
        auto *TRI = STI.getRegisterInfo();
        auto &MRI = MF->getRegInfo();

        auto Op = MF->getName().split('-').second.split('-').first;
        if (Op == "ADD64ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64ri8), X86::RCX)
              .addReg(X86::RCX)
              .addImm(0x25);
        if (Op == "ADD64mi32")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64mi32))
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addImm(0x25);
        if (Op == "ADD32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD32ri8), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        if (Op == "ADD64ri32")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64ri32), X86::RCX)
              .addReg(X86::RCX)
              .addImm(0x25);
        if (Op == "ADD64mi8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64mi8))
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addImm(0x25);
        if (Op == "ADD64mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64mr))
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::RAX);
        if (Op == "ADD64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64rm), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "ADD64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64rr), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX);
        if (Op == "ADC64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC64rr), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX);
        if (Op == "ADC64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC64rm), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "ADC64mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC64mr))
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::RAX);
        if (Op == "ADC32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC32ri8), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        if (Op == "ADD32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD32rr), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        if (Op == "ADD32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD32rm), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "ADD32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD32ri8), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        if (Op == "ADC32mi8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC32mi8))
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addImm(0x25);
        if (Op == "ADD8rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD8rm), X86::CL)
              .addReg(X86::CL)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "AND64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND64rr), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX);
        if (Op == "AND64ri32")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND64ri32), X86::RCX)
              .addReg(X86::RCX)
              .addImm(0x25);
        if (Op == "AND64ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND64ri8), X86::RCX)
              .addReg(X86::RCX)
              .addImm(0x25);
        if (Op == "AND32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND32rr), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        if (Op == "AND32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND32ri8), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        if (Op == "AND32ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND32ri), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        if (Op == "OR64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR64rr), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX);
        if (Op == "OR64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR64rm), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "OR64ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR64ri8), X86::RCX)
              .addReg(X86::RCX)
              .addImm(0x25);
        if (Op == "OR32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR32rr), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        if (Op == "OR32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR32ri8), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        if (Op == "OR8rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR8rm), X86::CL)
              .addReg(X86::CL)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "IMUL32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::IMUL32rm), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "XOR64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR64rr), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX);
        if (Op == "XOR64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR64rm), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "XOR64mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR64mr))
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::RAX);
        if (Op == "XOR32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR32rr), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        if (Op == "XOR32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR32rm), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "XOR32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR32ri8), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        // if (Op == "XOR8rr")
        //         BuildMI(*MBB, &MI, DL, TII->get(X86::XOR8rr),
        //         X86::CL).addReg(X86::CL).addReg(X86::AL);
        if (Op == "XOR8rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR8rm), X86::CL)
              .addReg(X86::CL)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "SUB64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB64rr), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX);
        if (Op == "SUB64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB64rm), X86::RCX)
              .addReg(X86::RCX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "SUB32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB32rr), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        if (Op == "TEST32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::TEST32rr))
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        // if (Op == "AND8rr")
        //         BuildMI(*MBB, &MI, DL, TII->get(X86::AND8rr),
        //         X86::CL).addReg(X86::CL).addReg(X86::AL);
        if (Op == "TEST8ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::TEST8ri))
              .addReg(X86::CL)
              .addImm(0x25);
        if (Op == "TEST8mi")
          BuildMI(*MBB, &MI, DL, TII->get(X86::TEST8mi))
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addImm(0x25);
        if (Op == "AND16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND16rr), X86::CX)
              .addReg(X86::CX)
              .addReg(X86::AX);
        if (Op == "OR16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR16rr), X86::CX)
              .addReg(X86::CX)
              .addReg(X86::AX);
        if (Op == "XOR16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR16rr), X86::CX)
              .addReg(X86::CX)
              .addReg(X86::AX);
        if (Op == "SUB16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB16rr), X86::CX)
              .addReg(X86::CX)
              .addReg(X86::AX);
        if (Op == "ADD16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD16rr), X86::CX)
              .addReg(X86::CX)
              .addReg(X86::AX);
        if (Op == "OR8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR8rr), X86::CL)
              .addReg(X86::CL)
              .addReg(X86::AL);
        if (Op == "SUB8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB8rr), X86::CL)
              .addReg(X86::CL)
              .addReg(X86::AL);
        if (Op == "ADD8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD8rr), X86::CL)
              .addReg(X86::CL)
              .addReg(X86::AL);
        if (Op == "SUB32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB32rm), X86::ECX)
              .addReg(X86::ECX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "SHR64rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR64rCL), X86::RCX)
              .addReg(X86::RCX);
        if (Op == "SHR32rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR32rCL), X86::ECX)
              .addReg(X86::ECX);
        if (Op == "SHL32rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL32rCL), X86::ECX)
              .addReg(X86::ECX);
        if (Op == "SHR16rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR16rCL), X86::CX)
              .addReg(X86::CX);
        if (Op == "SHL16rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL16rCL), X86::CX)
              .addReg(X86::CX);
        if (Op == "SHR8rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR8rCL), X86::CL)
              .addReg(X86::CL);
        if (Op == "SHL8rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL8rCL), X86::CL)
              .addReg(X86::CL);
        // if (Op == "SHR8ri")
        //         BuildMI(*MBB, &MI, DL, TII->get(X86::SHR8ri),
        //         X86::CL).addReg(X86::CL).addImm(0x25);
        if (Op == "SHR32ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR32ri), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        if (Op == "SHL32ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL32ri), X86::ECX)
              .addReg(X86::ECX)
              .addImm(0x25);
        if (Op == "SHL64ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL64ri), X86::RCX)
              .addReg(X86::RCX)
              .addImm(0x25);
        if (Op == "SAR64ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SAR64ri), X86::RCX)
              .addReg(X86::RCX)
              .addImm(0x25);
        if (Op == "SHR64ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR64ri), X86::RCX)
              .addReg(X86::RCX)
              .addImm(0x25);
        // if (Op == "SAR8r1")
        //         BuildMI(*MBB, &MI, DL, TII->get(X86::SAR8r1),
        //         X86::CL).addReg(X86::CL);
        if (Op == "SHR32r1")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR32r1), X86::ECX)
              .addReg(X86::ECX);
        if (Op == "SAR32r1")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SAR32r1), X86::ECX)
              .addReg(X86::ECX);
        if (Op == "MUL32r")
          BuildMI(*MBB, &MI, DL, TII->get(X86::MUL32r))
              .addReg(X86::ECX);
        if (Op == "CMP64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP64rr))
              .addReg(X86::RCX)
              .addReg(X86::RAX);
        if (Op == "CMP64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP64rm))
              .addReg(X86::RCX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "CMP32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP32rr))
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        if (Op == "CMP32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP32rm))
              .addReg(X86::ECX)
              .addReg(X86::EAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "CMP32mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP32mr))
              .addReg(X86::EAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::ECX);
        if (Op == "CMP8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP8rr))
              .addReg(X86::CL)
              .addReg(X86::AL);
        if (Op == "SUB8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB8rr))
              .addReg(X86::CL)
              .addReg(X86::AL);
        if (Op == "SBB32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SBB32rr))
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        if (Op == "IMUL32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::IMUL32rr))
              .addReg(X86::ECX)
              .addReg(X86::EAX);
        if (Op == "IMUL32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::IMUL32rm))
              .addReg(X86::ECX)
              .addReg(X86::RAX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "VPXORrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPXORrr))
              .addReg(X86::XMM0)
              .addReg(X86::XMM0)
              .addReg(X86::XMM1);
        if (Op == "VPXORrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPXORrm))
              .addReg(X86::XMM0)
              .addReg(X86::XMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "VPXORYrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPXORYrr))
              .addReg(X86::YMM0)
              .addReg(X86::YMM0)
              .addReg(X86::YMM1);
        if (Op == "VPXORYrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPXORYrm))
              .addReg(X86::YMM0)
              .addReg(X86::YMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "PXORrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::PXORrr))
              .addReg(X86::XMM0)
              .addReg(X86::XMM1);
        if (Op == "PXORrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::PXORrm))
              .addReg(X86::XMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "VPORrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPORrr))
              .addReg(X86::XMM0)
              .addReg(X86::XMM0)
              .addReg(X86::XMM1);
        if (Op == "VPORYrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPORYrr))
              .addReg(X86::YMM0)
              .addReg(X86::YMM0)
              .addReg(X86::YMM1);
        if (Op == "PORrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::PORrr))
              .addReg(X86::XMM0)
              .addReg(X86::XMM1);
        if (Op == "PORrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::PORrm))
              .addReg(X86::XMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "VPADDDrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPADDDrr))
              .addReg(X86::XMM0)
              .addReg(X86::XMM0)
              .addReg(X86::XMM1);
        if (Op == "VPADDDrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPADDDrm))
              .addReg(X86::XMM0)
              .addReg(X86::XMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "VPADDDYrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPADDDYrr))
              .addReg(X86::YMM0)
              .addReg(X86::YMM0)
              .addReg(X86::YMM1);
        if (Op == "VPADDDYrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPADDDYrm))
              .addReg(X86::YMM0)
              .addReg(X86::YMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "VPADDQrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPADDQrr))
              .addReg(X86::XMM0)
              .addReg(X86::XMM0)
              .addReg(X86::XMM1);
        if (Op == "VPADDQrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPADDQrm))
              .addReg(X86::XMM0)
              .addReg(X86::XMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "VPADDQYrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPADDQYrr))
              .addReg(X86::YMM0)
              .addReg(X86::YMM0)
              .addReg(X86::YMM1);
        if (Op == "VPADDQYrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::VPADDQYrm))
              .addReg(X86::YMM0)
              .addReg(X86::YMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        if (Op == "PADDQrr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::PADDQrr))
              .addReg(X86::XMM0)
              .addReg(X86::XMM1);
        if (Op == "PADDQrm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::PADDQrm))
              .addReg(X86::XMM0)
              .addReg(X86::RCX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        // TODO
        // ADD32i32
        // AND64i32
        // AND32i32
        // MUL64m
        // TEST8i8
      }
    }
  }
}

bool X86_64CompSimpMitigationPass::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableCompSimp)
    return false;

  if (MF.getName().startswith("x86compsimptest")) {
      setupTest(MF);
  }

  if (MF.getName().endswith("-original")) {
      return false;
  }

  if (false && !shouldRunOnMachineFunction(MF)) {
    return false; // Doesn't modify the func if not running
  }
  bool doesModifyFunction{false};

  std::vector<MachineInstr *> Instructions;
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      // Don't harden frame setup stuff like `push rbp`
      if (!MI.getFlag(MachineInstr::MIFlag::FrameSetup)) {
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

