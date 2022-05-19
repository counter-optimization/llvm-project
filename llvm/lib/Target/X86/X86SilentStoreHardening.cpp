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
        MachineFunction& MF) {
    DebugLoc DL = MI.getDebugLoc();
    const auto& STI = MF.getSubtarget();
    auto* TII = STI.getInstrInfo();
    auto* TRI = STI.getRegisterInfo();

    switch (MI.getOpcode()) {
        case X86::MOV8mr: {
            auto NumOperands = MI.getNumOperands();

            for (auto ii = 0; ii < NumOperands; ++ii) {
                errs() << "Operand " << ii << " is " << MI.getOperand(ii) << '\n';
            }

            auto& BaseRegMO = MI.getOperand(0);
            auto& ScaleMO = MI.getOperand(1);
            auto& IndexMO = MI.getOperand(2);
            auto& OffsetMO = MI.getOperand(3);
            auto& SegmentMO = MI.getOperand(4);
            auto& DestRegMO = MI.getOperand(5);

            errs() << "1\n";
            // addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV8rm), X86::R11B),
            //              BaseRegMO.getReg(), /*kills R11=*/true, OffsetMO.getImm());
            BuildMI(MBB, MI, DL, TII->get(X86::MOV8rm))
                .addReg(X86::R11B)
                .addReg(BaseRegMO.getReg())
                .addImm(1)
                .addReg(Register())
                .addImm(OffsetMO.getImm())
                .addReg(Register());

            errs() << "2\n";

            BuildMI(MBB, MI, DL, TII->get(X86::AND8ri8), X86::R11B)
                .addReg(X86::R11B)
                .addImm(0xF0);

            errs() << "3\n";
            BuildMI(MBB, MI, DL, TII->get(X86::NOT8r), Register(X86::R11B))
                .addReg(Register(X86::R11B));

            // addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr)), 
            //              BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm())
            //     .addReg(X86::R11B);
            errs() << "4\n";
            BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr))
                .addReg(BaseRegMO.getReg())
                .addImm(1)
                .addReg(Register())
                .addImm(OffsetMO.getImm())
                .addReg(Register())
                .addReg(X86::R11B);
            errs() << "5\n";
            BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), X86::R11B)
                .addReg(DestRegMO.getReg());
            errs() << "6\n";
            BuildMI(MBB, MI, DL, TII->get(X86::AND8ri8), X86::R11B)
                .addReg(X86::R11B)
                .addImm(0x0F); 
            errs() << "7\n";
            BuildMI(MBB, MI, DL, TII->get(X86::NOT8r), Register(X86::R11B))
                .addReg(Register(X86::R11B));
            errs() << "8\n";
            auto MIB = BuildMI(MBB, MI, DL, TII->get(X86::OR8rm), X86::R11B); 
            MIB.addReg(X86::R11B);
            addRegOffset(MIB, BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm());
            // addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::OR8rm), X86::R11B), 
            //              BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm());
            // auto MIB = BuildMI(MBB, MI, DL, TII->get(X86::OR8rm));
            //     errs() << "A\n";
            //     MIB.addReg(X86::R11B);
            //     errs() << "AA\n";
            //     MIB.addReg(X86::R11B);
            //     errs() << "B\n";
            //     MIB.addReg(BaseRegMO.getReg());
            //     errs() << "C\n";
            //     MIB.addImm(1);
            //     errs() << "D\n";
            //     MIB.addReg(Register());
            //     errs() << "E\n";
            //     MIB.addImm(OffsetMO.getImm());
            //     errs() << "F\n";
            //     MIB.addReg(Register());
            errs() << "9\n";
            // addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr)), 
            //              BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm())
            //             .addReg(X86::R11B);
            BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr))
                .addReg(BaseRegMO.getReg()) // Base
                .addImm(1) // Scale
                .addReg(Register()) // Index
                .addImm(OffsetMO.getImm()) // Disp/offset
                .addReg(Register()) // Segment reg
                .addReg(X86::R11B);
            errs() << "10\n";
            // END OF NEW CHANGES
            // BuildMI(MBB, MI, DL, TII->get(X86::XOR64rr), X86::R11)
            //     .addReg(X86::R11);

            // // Read secret into scratch
            // BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), X86::R11B)
            //     .addReg(DestRegMO.getReg());

            // BuildMI(MBB, MI, DL, TII->get(X86::SHL64ri), X86::R11)
            //     .addReg(X86::R11)
            //     .addImm(32);

            // // Insert insn to read the contents of destination address into R11
            // addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV8rm), X86::R11B),
            //              BaseRegMO.getReg(), /*kills R11=*/true, OffsetMO.getImm());

            // // Insert insn to zero out the low 4bits of R11 (aka R11D)
            // BuildMI(MBB, MI, DL, TII->get(X86::AND8ri8), Register(X86::R11B))
            //     .addReg(Register(X86::R11))
            //     .addImm(0xF0);

            // // Insert insn to move the secret data into the low 4bits of R11
            // BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), Register(X86::R11B))
            //     .addReg(DestRegMO.getReg());

            // // Insert insn to bitwise not all of R11
            // BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), Register(X86::R11))
            //     .addReg(Register(X86::R11));

            // // Insert insn to store R11, whose contents is NOT EQUAL to the contents
            // // of (BaseRegMO + OffsetMO) or DestRegMO
            // addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr)), 
            //              BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm())
            //     .addReg(X86::R11);

            break;
        }
        case X86::MOV64mr: {
            /*
            MI has 6 operands
            Operand: $rbp // Base register
            Operand: 1 // Scale amount
            Operand: $noreg // Index register
            Operand: -8 // Address offset
            Operand: $noreg // Segment register
            Operand: renamable $rdi // Destination
            See lib/Target/X86/MCTargetDesc/X86BaseInfo.h.
            */
            auto& BaseRegMO = MI.getOperand(0);
            auto& ScaleMO = MI.getOperand(1);
            auto& IndexMO = MI.getOperand(2);
            auto& OffsetMO = MI.getOperand(3);
            auto& SegmentMO = MI.getOperand(4);
            auto& DestRegMO = MI.getOperand(5);

            // Insert insn to read the contents of destination address into R11
            addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), X86::R11),
                         BaseRegMO.getReg(), /*kills R11=*/true, OffsetMO.getImm());

            // Insert insn to zero out the low 32 bits of r11d
            BuildMI(MBB, MI, DL, TII->get(X86::AND32ri8), Register(X86::R11D))
                .addReg(Register(X86::R11D))
                .addImm(0);

            // Insert insn to move the secret data into the low 8bits of R11
            BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), Register(X86::R11B))
                .addReg(DestRegMO.getReg());

            // Insert insn to bitwise not all of R11
            BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), Register(X86::R11))
                .addReg(Register(X86::R11));

            // Insert insn to store R11, whose contents is NOT EQUAL to the contents
            // of (BaseRegMO + OffsetMO) or DestRegMO
            addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr)), 
                         BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm())
                .addReg(X86::R11);

            // No need to insert the actual store of the sensitive data. All of
            // the previously inserted insns are all inserted before the store
            // of the sensitive data, so it's already there.
            break;
        }
        // case X86::MOV64mi32: {
        //     break;
        //     auto NumOperands = MI.getNumOperands();

        //     for (auto ii = 0; ii < NumOperands; ++ii) {
        //         errs() << "Operand " << ii << " is " << MI.getOperand(ii) << '\n';
        //     }
        //     /*
        //     MI has 6 operands
        //     Operand: $rbp // Base register
        //     Operand: 1 // Scale amount
        //     Operand: $noreg // Index register
        //     Operand: -8 // Address offset
        //     Operand: $noreg // Segment register
        //     Operand: renamable $rdi // Destination
        //     See lib/Target/X86/MCTargetDesc/X86BaseInfo.h.
        //     */
        //     auto& BaseRegMO = MI.getOperand(0);
        //     auto& ScaleMO = MI.getOperand(1);
        //     auto& IndexMO = MI.getOperand(2);
        //     auto& OffsetMO = MI.getOperand(3);
        //     auto& SegmentMO = MI.getOperand(4);
        //     auto& DestRegMO = MI.getOperand(5);

        //     // Insert insn to read the contents of destination address into R11
        //     addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), X86::R11),
        //                  BaseRegMO.getReg(), /*kills R11=*/true, OffsetMO.getImm());

        //     // Insert insn to zero out the low 32bits of R11 (aka R11D)
        //     BuildMI(MBB, MI, DL, TII->get(X86::AND32ri8), Register(X86::R11D))
        //         .addReg(Register(X86::R11D))
        //         .addImm(0);

        //     // Insert insn to move the secret data into the low 32bits of R11
        //     // (aka R11D)    
        //     BuildMI(MBB, MI, DL, TII->get(X86::MOV32rr), Register(X86::R11D))
        //         .addReg(DestRegMO.getImm());

        //                 // Insert insn to bitwise not all of R11
        //     BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), Register(X86::R11))
        //         .addReg(Register(X86::R11));

        //     // Insert insn to store R11, whose contents is NOT EQUAL to the contents
        //     // of (BaseRegMO + OffsetMO) or DestRegMO
        //     addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr)), 
        //                  BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm())
        //         .addReg(X86::R11);


        //     break;
        // }
        default: {
            errs() << "Unsupported opcode: " << TII->getName(MI.getOpcode()) << '\n';
            // assert(false && "Unsupported opcode in X86SilentStoreHardening");
            break;
        }
    }
}

bool X86_64SilentStoreMitigationPass::runOnMachineFunction(MachineFunction& MF) {
    if (!shouldRunOnMachineFunction(MF)) {
        return false; // Doesn't modify the func if not running
    }

    bool doesModifyFunction{false};
    for (auto& MBB : MF) {
        for (auto& MI : MBB) {
            // Don't harden frame setup stuff like `push rbp`
            if (MI.mayStore() && !MI.getFlag(MachineInstr::MIFlag::FrameSetup)) {
                doX86SilentStoreHardening(MI, MBB, MF);
                doesModifyFunction = true; // Modifies the func if it does run
            }
        }
        errs() << MBB << '\n';
    }

    return doesModifyFunction;
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