#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
/* #include "llvm/Target/TargetRegisterInfo.h" */

// using namespace llvm;

// initializeX86MachineInstrPrinterPass

// #define X86_MACHINEINSTR_PRINTER_PASS_NAME "Dummy X86 machineinstr printer pass"

// namespace {

// class X86MachineInstrPrinter : public MachineFunctionPass {
// public:
//     static char ID;

//     X86MachineInstrPrinter() : MachineFunctionPass(ID) {
//         initializeX86MachineInstrPrinterPass(*PassRegistry::getPassRegistry());
//     }

//     bool runOnMachineFunction(MachineFunction &MF) override;
//     void getAnalysisUsage(AnalysisUsage &AU) const override;

//     StringRef getPassName() const override { 
//         return X86_MACHINEINSTR_PRINTER_PASS_NAME; 
//     }
// private:
//     std::vector<MCRegister> getTaintedLiveIns(const MachineFunction &MF, const Function &F) const;
// };

// char X86MachineInstrPrinter::ID = 0;

// bool X86MachineInstrPrinter::runOnMachineFunction(MachineFunction &MF) {
//     // get the LLVM IR function which will be used for finding the vars
//     // marked by llvm.var.annotate intrinsic
//     const Function& F = MF.getFunction();
//     const MachineRegisterInfo& MRI = MF.getRegInfo();
//     const TargetRegisterInfo* TRI = MRI.getTargetRegisterInfo();

//     for (MachineBasicBlock &MBB : MF) {
//         errs() << "MF is: " << MF.getName() << '\n';

//         // Live Ins printing
//         errs() << "liveins are: ";
//         for (const auto &RegPair : MRI.liveins()) {
//             MCRegister MCR;
//             Register Reg;
//             std::tie(MCR, Reg) = RegPair;

//             errs() << MCR << "," << Reg << '|';
//             errs() << TRI->getRegAsmName(MCR) << ",";
//         }
//         errs() << '\n';

//         // Process store instructions
//         for (MachineInstr &MI : MBB) {
//             if (MI.mayStore()) {
//                 errs() << "\tstore instr is: " << MI;
//             }
//         }
//     }

//     return false;
// }

// std::vector<MCRegister> X86MachineInstrPrinter::getTaintedLiveIns(
//         const MachineFunction &MF, const Function &F) const {
//     std::vector<MCRegister> taintedLiveIns;
//     return taintedLiveIns;
// }

// void X86MachineInstrPrinter::getAnalysisUsage(AnalysisUsage &AU) const {
//     MachineFunctionPass::getAnalysisUsage(AU);
//     AU.setPreservesCFG();
// }

// } // end of anonymous namespace

// INITIALIZE_PASS(X86MachineInstrPrinter, "x86-machineinstr-printer",
//     X86_MACHINEINSTR_PRINTER_PASS_NAME,
//     true, // is CFG only?
//     true  // is analysis?
// )

// FunctionPass* llvm::createX86MachineInstrPrinterPass() { 
//     return new X86MachineInstrPrinter(); 
// }