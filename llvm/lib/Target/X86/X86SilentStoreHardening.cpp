#include <fstream>
#include <sstream>
#include <string>

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

private:
    /* The number of instructions coming before this instruction.
     * This is 0 for the first instruction of the function, 1 for the
     * next insn, ...
     */
    size_t InstructionIdx = 0;

    /* Number of instructions instrumented so far. This should match
     * the number of alerts in the csv file from the checker.
     */
    size_t NumInstrumented = 0;

    std::vector<size_t> IndicesToInstrument;

    void doX86SilentStoreHardening(MachineInstr& MI,
        MachineBasicBlock& MBB,
        MachineFunction& MF);

    struct CheckerAlertCSVLine {
        bool SilentStore;
        bool CompSimp;
        bool Dmp;
        size_t InsnIdx;

        CheckerAlertCSVLine(std::string Line) {
            std::istringstream StrReader(Line);

            constexpr size_t NumCols = 4;
            std::array<unsigned int, NumCols> Cols;
            char ColChars[512] = {0};
            size_t ColsRead = 0;

            while (StrReader.getline(ColChars, 512, ',')) {
                unsigned int CurColValue = std::stoul(std::string(ColChars));
                Cols[ColsRead++] = CurColValue;
            }

            assert(ColsRead == NumCols && "Checker alert CSV col header mismatch.");

            SilentStore = Cols[0] == 1UL;
            CompSimp = Cols[1] == 1UL;
            Dmp = Cols[2] == 1UL;
            InsnIdx = Cols[3];
        }
    };

    std::vector<CheckerAlertCSVLine> RelevantCSVLines;

    void readCheckerAlertCSV(std::string Filename);
    bool isRelevantCheckerAlertCSVLine(CheckerAlertCSVLine &Line);
};

/*
 * The CSV file has the following header:
 * harden_silentstore,harden_compsimp,harden_dmp,insn_idx
 */
void X86_64SilentStoreMitigationPass::readCheckerAlertCSV(std::string Filename) {
    std::ifstream IFS(Filename);

    if (!IFS.is_open()) {
        errs() << "Couldn't open file " << Filename << " from checker.\n";
        assert(IFS.is_open() && "Couldn't open checker alert csv.\n");
    }

    constexpr size_t MaxLineSize = 512; // 512 chars should be more than enough
    char Line[MaxLineSize] = {0};
    std::string ExpectedHeader("harden_silentstore,harden_compsimp,harden_dmp,insn_idx");
    bool IsHeader = true;

    // operator bool() on the returned this* from .getline returns 
    // false. i think it returns false when EOF is hit? 
    while (IFS.getline(Line, MaxLineSize)) {
        std::string CurrentLine(Line);

        if (IsHeader) {
            assert(ExpectedHeader == CurrentLine && "Unexpected header in checker alert csv file");
            IsHeader = false;
        } else {
            CheckerAlertCSVLine CSVLine(CurrentLine);

            if (isRelevantCheckerAlertCSVLine(CSVLine)) {
                RelevantCSVLines.push_back(CSVLine);
                IndicesToInstrument.push_back(CSVLine.InsnIdx);
            }
        }
    }
}

bool X86_64SilentStoreMitigationPass::isRelevantCheckerAlertCSVLine(CheckerAlertCSVLine &Line) {
    return Line.SilentStore;
}

void X86_64SilentStoreMitigationPass::doX86SilentStoreHardening(
        MachineInstr& MI, 
        MachineBasicBlock& MBB, 
        MachineFunction& MF) {

    DebugLoc DL = MI.getDebugLoc();
    const auto& STI = MF.getSubtarget();
    auto* TII = STI.getInstrInfo();
    auto* TRI = STI.getRegisterInfo();
    auto& MRI = MF.getRegInfo();

    bool OpcodeSupported = true;

    switch (MI.getOpcode()) {
        case X86::MOV8mr:
        case X86::MOV8mi: 
        {
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

            BuildMI(MBB, MI, DL, TII->get(X86::MOV8rm))
                .addReg(X86::R11B)
                .addReg(BaseRegMO.getReg())
                .addImm(1)
                .addReg(Register())
                .addImm(OffsetMO.getImm())
                .addReg(Register());

            BuildMI(MBB, MI, DL, TII->get(X86::AND8ri8), X86::R11B)
                .addReg(X86::R11B)
                .addImm(0xF0);

            BuildMI(MBB, MI, DL, TII->get(X86::NOT8r), Register(X86::R11B))
                .addReg(Register(X86::R11B));

            BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr))
                .addReg(BaseRegMO.getReg())
                .addImm(1)
                .addReg(Register())
                .addImm(OffsetMO.getImm())
                .addReg(Register())
                .addReg(X86::R11B);

            if (DestRegMO.isImm()) {
                 BuildMI(MBB, MI, DL, TII->get(X86::MOV8ri), X86::R11B)
                    .addImm(DestRegMO.getImm());
            } else {
                BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), X86::R11B)
                    .addReg(DestRegMO.getReg());
            }
            
            BuildMI(MBB, MI, DL, TII->get(X86::AND8ri8), X86::R11B)
                .addReg(X86::R11B)
                .addImm(0x0F); 

            BuildMI(MBB, MI, DL, TII->get(X86::NOT8r), Register(X86::R11B))
                .addReg(Register(X86::R11B));
        
            auto MIB = BuildMI(MBB, MI, DL, TII->get(X86::OR8rm), X86::R11B); 
            MIB.addReg(X86::R11B);
            addRegOffset(MIB, BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm());

            BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr))
                .addReg(BaseRegMO.getReg()) // Base
                .addImm(1) // Scale
                .addReg(Register()) // Index
                .addImm(OffsetMO.getImm()) // Disp/offset
                .addReg(Register()) // Segment reg
                .addReg(X86::R11B);
            break;
        }
        case X86::MOV32mr:
        case X86::MOV32mi:
        {
            auto& BaseRegMO = MI.getOperand(0);
            auto& ScaleMO = MI.getOperand(1);
            auto& IndexMO = MI.getOperand(2);
            auto& OffsetMO = MI.getOperand(3);
            auto& SegmentMO = MI.getOperand(4);
            auto& DestRegMO = MI.getOperand(5);

            // Insert insn to read the contents of destination address into R11
            // mov32rm r11d, [baseregmo + offsetmo]
            addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV32rm), X86::R11D),
                         BaseRegMO.getReg(), /*kills R11=*/true, OffsetMO.getImm());

            // Insert insn to move the secret data into the low 16bits of R11
            if (DestRegMO.isImm()) {
                // TODO: This needs to be checked to not truncate the value
                 BuildMI(MBB, MI, DL, TII->get(X86::MOV16ri), Register(X86::R11W))
                    .addImm(DestRegMO.getImm());
            } else {
                Register fixedWidthDestReg = DestRegMO.getReg();
                if (16 < TRI->getRegSizeInBits(DestRegMO.getReg(), MRI)) {
                    // sub reg index 4 is 
                    // each 32/64 bit gpr's word sized subregister
                    fixedWidthDestReg = TRI->getSubReg(fixedWidthDestReg, 4);
                }
                BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), Register(X86::R11W))
                    .addReg(fixedWidthDestReg);
            }

            // Insert insn to bitwise not all of R11
            BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), Register(X86::R11))
                .addReg(Register(X86::R11));

            // Insert insn to store R11, whose contents is NOT EQUAL to the contents
            // of (BaseRegMO + OffsetMO) or DestRegMO
            addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV32mr)), 
                         BaseRegMO.getReg(), /*kills dest=*/false, OffsetMO.getImm())
                .addReg(X86::R11D);

            // No need to insert the actual store of the sensitive data. All of
            // the previously inserted insns are all inserted before the store
            // of the sensitive data, so it's already there.
            break;
        }
        case X86::MOV64mr:
        case X86::MOV64mi32:
        {
            auto& BaseRegMO = MI.getOperand(0);
            auto& ScaleMO = MI.getOperand(1);
            auto& IndexMO = MI.getOperand(2);
            auto& OffsetMO = MI.getOperand(3);
            auto& SegmentMO = MI.getOperand(4);
            auto& DestRegMO = MI.getOperand(5);

            // Insert insn to read the contents of destination address into R11
            if (DestRegMO.isReg()) {
                addRegOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), X86::R11),
                             BaseRegMO.getReg(), /*kills R11=*/true, OffsetMO.getImm());
            }

            // Insert insn to zero out the low 32 bits of r11d
            BuildMI(MBB, MI, DL, TII->get(X86::AND32ri8), Register(X86::R11D))
                .addReg(Register(X86::R11D))
                .addImm(0);

            // Insert insn to move the secret data into the low 8bits of R11
            if (DestRegMO.isImm()) {
                 BuildMI(MBB, MI, DL, TII->get(X86::MOV8ri), Register(X86::R11B))
                    .addImm(DestRegMO.getImm());
            } else {
                auto SRIByte = TRI->getSubRegIndex(MCRegister(X86::RAX), MCRegister(X86::AL));
                auto SRIWord = TRI->getSubRegIndex(MCRegister(X86::RAX), MCRegister(X86::AX));
                auto SRIDouble = TRI->getSubRegIndex(MCRegister(X86::RAX), MCRegister(X86::EAX));
                errs() << "SRIByte: " << SRIByte << '\n';
                errs() << "SRIWord: " << SRIWord << '\n';
                errs() << "SRIDouble: " << SRIDouble << '\n';
                errs() << "Subregidx ax of eax: " 
                       << TRI->getSubRegIndex(MCRegister(X86::EAX), MCRegister(X86::AX))
                       << '\n';

                Register fixedWidthDestReg = DestRegMO.getReg();
                if (8 < TRI->getRegSizeInBits(DestRegMO.getReg(), MRI)) {
                    // 1 should be the smallest, least significant subreg
                    fixedWidthDestReg = TRI->getSubReg(fixedWidthDestReg, 1);
                }
                BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), Register(X86::R11B))
                    .addReg(fixedWidthDestReg);
            }

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
        default: 
        {
            errs() << "Unsupported opcode: " << TII->getName(MI.getOpcode()) << '\n';
            OpcodeSupported = false;
            // assert(false && "Unsupported opcode in X86SilentStoreHardening");
            break;
        }
    }

    if (OpcodeSupported) { // then it was instrumented
        NumInstrumented += 1;
    }
}

bool X86_64SilentStoreMitigationPass::runOnMachineFunction(MachineFunction& MF) {
    if (!shouldRunOnMachineFunction(MF)) {
        return false; // Doesn't modify the func if not running
    }

    readCheckerAlertCSV("test_alert.csv");

    bool doesModifyFunction{false};

    for (auto& MBB : MF) {
        for (auto& MI : MBB) {
            // Don't harden frame setup stuff like `push rbp`
            if (MI.mayStore() && !MI.getFlag(MachineInstr::MIFlag::FrameSetup)) {
                doX86SilentStoreHardening(MI, MBB, MF);
                doesModifyFunction = true; // Modifies the func if it does run
            }

            InstructionIdx += 1;
        }
        // errs() << MBB << '\n';
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