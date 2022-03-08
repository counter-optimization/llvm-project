#include "MCTargetDesc/X86BaseInfo.h"
#include "X86FrameLowering.h"
#include "X86InstrInfo.h"
#include "X86TargetMachine.h"
#include "X86InstrBuilder.h"
#include "X86.h"
#include "X86MachineFunctionInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/DebugLoc.h"

#include "llvm/Pass.h"

namespace llvm {

void initializeX86_64SilentStoreMitigationPassPass(PassRegistry &);

class X86_64SilentStoreMitigationPass : public MachineFunctionPass {
public:
    static char ID;

    X86_64SilentStoreMitigationPass() : MachineFunctionPass(ID) {
        initializeX86_64SilentStoreMitigationPassPass(*PassRegistry::getPassRegistry());
    }

    ~X86_64SilentStoreMitigationPass() = default;

    bool runOnMachineFunction(MachineFunction &MF) override;

    bool shouldRunOnMachineFunction(MachineFunction &MF);

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        MachineFunctionPass::getAnalysisUsage(AU);
        AU.setPreservesCFG();
    }

    StringRef getPassName() const override {
        return "Silent stores mitigations";
    }
};

// 1. Move contents of Address into r11 (saved by reg alloc)
// 2. Mask off the bottom half bits of r11
// 3. Move SensitiveData holding register into r11d
// 4. Bitwise not r11 into r11
// 5. Store r11 into Address
// 6. Store SensitiveData into Address
void doX86SilentStoreHardening(
        MachineInstr& MI, 
        MachineBasicBlock& MBB, 
        MachineBasicBlock::iterator& MBBI,
        MachineFunction& MF) {
    DebugLoc DL = MI.getDebugLoc();
    const auto& STI = MF.getSubtarget();
    auto* TII = STI.getInstrInfo();
    auto* TRI = STI.getRegisterInfo();

    // auto MBBI = MBB.instr_begin();
    // while (*MBBI != MI) { 
    //     MBBI++;
    // }
    // errs() << "MBBI is at insn: " << *MBBI << '\n';

    switch (MI.getOpcode()) {
        case X86::MOV64mr: {
            /*
            MI has 6 operands
            Operand: $rbp
            Operand: 1
            Operand: $noreg
            Operand: -8
            Operand: $noreg
            Operand: renamable $rdi
            */
            auto& Address = MI.getOperand(0);
            auto& Offset = MI.getOperand(3);
            auto& SensitiveData = MI.getOperand(5);
            errs() << "Offset isImm?: " << Offset.isImm() << '\n';
            errs() << "Address isReg?: " << Address.isReg() << '\n';
            errs() << "SensitiveData isReg?: " << SensitiveData.isReg() << '\n';
            // BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), Register(X86::R11))
            // BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm))
            //     .addReg(Register(X86::R11))
            //     .addImm(Offset.getImm())
            //     .addReg(Address.getReg());
            addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), X86::R11),
                         Address.getReg(), true, Offset.getImm());
            BuildMI(MBB, MI, DL, TII->get(X86::AND32ri8), Register(X86::R11D))
                .addReg(Register(X86::R11D))
                .addImm(0);
            BuildMI(MBB, MI, DL, TII->get(X86::MOV32rr), Register(X86::R11D))
                .addReg(SensitiveData.getReg());
            BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), Register(X86::R11))
                .addReg(Register(X86::R11));

            // BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr), Register(X86::RBP))
            // BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
            //     .addReg(Address.getReg())
            //     .addImm(Offset.getImm())
            //     .addReg(Register(X86::R11));
            // BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr), X86::RBP, false, Offset.getImm())
            //     .addReg(X86::R11);
            addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr)), X86::RBP, false, Offset.getImm())
                .addReg(X86::R11);
            // BuildMI(MBB, MBBI, DL, TII->get(X86::MOV64mr), X86::RBP, false, Offset.getImm())
                // .addReg(X86::R11);

            // BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr), Register(X86::RBP))
            // BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
            //     .addReg(Address.getReg())
            //     .addImm(Offset.getImm())
            //     .addReg(SensitiveData.getReg());
            // BuildMI(MBB, MBBI, DL, TII->get(X86::MOV64mr), Address.getReg(), false, Offset.getImm())
            //     .addReg(SensitiveData.getReg());
            // addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr)), Address.getReg(), false, Offset.getImm())
            //     .addReg(SensitiveData.getReg());
            break;
        }
        default: {
            errs() << "Unsupported opcode: " << MI.getOpcode() << '\n';
            break;
        }
    }
}

bool X86_64SilentStoreMitigationPass::runOnMachineFunction(MachineFunction& MF) {
    if (!shouldRunOnMachineFunction(MF)) {
        return false;
    }

    for (auto& MBB : MF) {
        for (auto MBBI = MBB.begin(); MBBI != MBB.end(); MBBI++) {
            auto& MI = *MBBI;
            if (MI.mayStore()) {
                errs() << "Function " << MF.getName() << " instr " << MI;
                errs() << " may store.";

                // dont harden initial `push rbp`
                if (!MI.getFlag(MachineInstr::MIFlag::FrameSetup)) {
                    doX86SilentStoreHardening(MI, MBB, MBBI, MF);

                    errs() << "MI has " << MI.getNumOperands() << " operands\n";
                    const auto& OP0 = MI.getOperand(0);
                    for (auto& OP : MI.operands()) {
                        errs() << "\t\tOperand: " << OP << '\n';
                    }
                }
            }
        }
        errs() << MBB << '\n';
    }

    return true;
}

// This will eventually check for the secret attribute. For now, just use function names.
bool X86_64SilentStoreMitigationPass::shouldRunOnMachineFunction(MachineFunction& MF) {
    Function& F = MF.getFunction();

    for (auto& Arg : F.args()) {
        if (Arg.hasAttribute(Attribute::Secret)) {
            return true;
        }
    }

    return false;
}

char X86_64SilentStoreMitigationPass::ID = 0;

FunctionPass* createX86_64SilentStoreMitigationPass() {
    return new X86_64SilentStoreMitigationPass();
}

INITIALIZE_PASS(X86_64SilentStoreMitigationPass, "ss",
            "Mitigations for silent store optimizations", true, true)

} // end namespace llvm