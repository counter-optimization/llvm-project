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

using namespace llvm;

namespace {

class X86_64SilentStoreMitigationPass : public MachineFunctionPass {
public:
    static char ID;

    X86_64SilentStoreMitigationPass() : MachineFunctionPass(ID) {
    }

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
} // end anonymous namespace 

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

static Register getEqR10(Register EAX){
    switch(EAX) {
        case X86::RAX:
            return X86::R10;
        case X86::EAX:
            return X86::R10D;
        case X86::AX:
            return X86::R10W;
        case X86::AH:
            return X86::R10BH;
        case X86::AL:
            return X86::R10B;
        default:
            return EAX;
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
  const auto &STI = MF.getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF.getRegInfo();

  bool OpcodeSupported = true;

  switch (MI.getOpcode()) {
  case X86::MOV8mr:
  case X86::MOV8mi: {
    auto NumOperands = MI.getNumOperands();
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    /* Handle EFLAGS
     * mov r10 eax
     * mov eax eflags
     *
     * mov eflags eax
     * mov eax 10
     *
     * or
     *
     * blind move
     * push eflags
     * pop r10
     *
     * push r10
     * pop eflags
     * blind move
     */

    /* EFLAG hack 1
     * MachineInstr *Push = BuildMI(MBB, MI, DL, TII->get(X86::PUSHF32));
     * Push->getOperand(2).setIsUndef();
     * Push->getOperand(3).setIsUndef();
     */

    // EFLAG hack 2
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(X86::RAX);
    BuildMI(MBB, MI, DL, TII->get(X86::LAHF));

    // TODO Use XCHG
    // BuildMI(MBB, MI, DL,
    // TII->get(X86::XCHG64rr)).addReg(X86::RAX).addReg(X86::R10).addReg(X86::RAX).addReg(X86::R10);

    /* EFLAG hack 3
     * MachineInstr *Push = BuildMI(MBB, MI, DL, TII->get(X86::PUSHF32));
     * Push->getOperand(2).setIsUndef();
     * Push->getOperand(3).setIsUndef();
     * BuildMI(MBB, MI, DL, TII->get(X86::POP32r)).addReg(X86::R10D);
     */

    Register B, S, I, D;
    if (BaseRegMO.isReg())
      B = getEqR10(BaseRegMO.getReg());
    if (DestRegMO.isReg())
      D = getEqR10(DestRegMO.getReg());
    if (SegmentMO.isReg())
      S = getEqR10(SegmentMO.getReg());
    if (IndexMO.isReg())
      I = getEqR10(IndexMO.getReg());

    auto MOV1 = BuildMI(MBB, MI, DL, TII->get(X86::MOV8rm), X86::R11B)
                    .addReg(B)
                    .add(ScaleMO);
    if (IndexMO.isReg())
      MOV1.addReg(I);
    else
      MOV1.add(IndexMO);
    MOV1.add(OffsetMO);
    if (SegmentMO.isReg())
      MOV1.addReg(S);
    else
      MOV1.add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::AND8ri), Register(X86::R11B))
        .addUse(X86::R11B)
        .addImm(0xF0);

    BuildMI(MBB, MI, DL, TII->get(X86::NOT8r), Register(X86::R11B))
        .addReg(Register(X86::R11B));

    auto MOV2 =
        BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr)).addReg(B).add(ScaleMO);
    if (IndexMO.isReg())
      MOV2.addReg(I);
    else
      MOV2.add(IndexMO);
    MOV2.add(OffsetMO);
    if (SegmentMO.isReg())
      MOV2.addReg(S);
    else
      MOV2.add(SegmentMO);
    MOV2.addDef(X86::R11B);

    if (DestRegMO.isImm()) {
      BuildMI(MBB, MI, DL, TII->get(X86::MOV8ri), X86::R11B)
          .addImm(DestRegMO.getImm());
    } else {
      BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(D);
    }

    BuildMI(MBB, MI, DL, TII->get(X86::AND8ri), X86::R11B)
        .addUse(X86::R11B)
        .addImm(0x0F);

    BuildMI(MBB, MI, DL, TII->get(X86::NOT8r), Register(X86::R11B))
        .addReg(Register(X86::R11B));

    auto OR1 = BuildMI(MBB, MI, DL, TII->get(X86::OR8rm), X86::R11B)
                   .addUse(X86::R11B)
                   .addReg(B)
                   .add(ScaleMO);
    if (IndexMO.isReg())
      OR1.addReg(I);
    else
      OR1.add(IndexMO);

    OR1.add(OffsetMO);
    if (SegmentMO.isReg())
      OR1.addReg(S);
    else
      OR1.add(SegmentMO);

    auto MOV3 = BuildMI(MBB, MI, DL, TII->get(X86::MOV8mr))
                    .addReg(B)     // Base
                    .add(ScaleMO); // Scale
    if (IndexMO.isReg())
      MOV3.addReg(I);
    else
      MOV3.add(IndexMO);

    MOV3.add(OffsetMO); // Disp/offset
    if (SegmentMO.isReg())
      MOV3.addReg(S);
    else
      MOV3.add(SegmentMO);

    MOV3.addReg(X86::R11B);

    // TODO Use XCHG
    // BuildMI(MBB, MI, DL,
    // TII->get(X86::XCHG64rr),X86::RAX).addReg(X86::R10).addUse(X86::RAX).addUse(X86::R10);
    BuildMI(MBB, MI, DL, TII->get(X86::SAHF));
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R10);

    /* EFLAG hack 3
     * BuildMI(MBB, MI, DL, TII->get(X86::PUSH32r)).addReg(X86::R10D);
     * MachineInstr *Pop = BuildMI(MBB, MI, DL, TII->get(X86::POPF32));
     */
    break;
  }
  case X86::MOV16mr:
  case X86::MOV16mi: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    // Insert insn to read the contents of destination address into R11
    // mov16rm r11w, [baseregmo + offsetmo]
    auto Load = BuildMI(MBB, MI, DL, TII->get(X86::MOV16rm), X86::R11W)
                    .addReg(BaseRegMO.getReg())
                    .add(ScaleMO) // Scale
                    .add(IndexMO) // Index
                    .add(OffsetMO)
                    .add(SegmentMO);

    // Insert insn to move the secret data into the low 8bits of R11
    if (DestRegMO.isImm()) {
      // TODO: This needs to be checked to not truncate the value
      BuildMI(MBB, MI, DL, TII->get(X86::MOV8ri), X86::R11B)
          .addImm(DestRegMO.getImm());
    } else {
      assert(DestRegMO.isReg() && "must be reg");
      Register fixedWidthDestReg = DestRegMO.getReg();
      if (8 < TRI->getRegSizeInBits(DestRegMO.getReg(), MRI)) {
        fixedWidthDestReg = TRI->getSubReg(fixedWidthDestReg, 1);
      }
      BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), Register(X86::R11B))
          .addReg(fixedWidthDestReg);
    }

    // Insert insn to bitwise not all of R11
    BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), Register(X86::R11))
        .addReg(Register(X86::R11));

    // Insert insn to store R11, whose contents is NOT EQUAL to the
    // contents of (BaseRegMO + OffsetMO) or DestRegMO
    auto ProxyStore = BuildMI(MBB, MI, DL, TII->get(X86::MOV16mr))
                          .addReg(BaseRegMO.getReg()) // Base
                          .add(ScaleMO)               // Scale
                          .add(IndexMO)               // Index
                          .add(OffsetMO)              // Disp/offset
                          .add(SegmentMO)             // Segment reg
                          .addReg(X86::R11W);

    // No need to insert the actual store of the sensitive data. All of
    // the previously inserted insns are all inserted before the store
    // of the sensitive data, so it's already there.
    break;
  }
  case X86::MOV32mr:
  case X86::MOV32mi: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    // MachineInstr *MI2 =
    //     addOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV32rm), X86::R11D)
    //                   .addReg(BaseRegMO.getReg()),
    //               OffsetMO);

    // Insert insn to read the contents of destination address into R11
    // mov32rm r11d, [baseregmo + offsetmo]
    auto Load = BuildMI(MBB, MI, DL, TII->get(X86::MOV32rm), X86::R11D)
                    .addReg(BaseRegMO.getReg())
                    .add(ScaleMO) // Scale
                    .add(IndexMO) // Index
                    .add(OffsetMO)
                    .add(SegmentMO);
 
    // Insert insn to move the secret data into the low 16bits of R11
    if (DestRegMO.isImm()) {
      // TODO: This needs to be checked to not truncate the value
      BuildMI(MBB, MI, DL, TII->get(X86::MOV16ri), X86::R11W)
          .addImm(DestRegMO.getImm());
    } else {
      assert(DestRegMO.isReg() && "must be reg");
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

    // Insert insn to store R11, whose contents is NOT EQUAL to the
    // contents of (BaseRegMO + OffsetMO) or DestRegMO
    auto ProxyStore = BuildMI(MBB, MI, DL, TII->get(X86::MOV32mr))
                          .addReg(BaseRegMO.getReg()) // Base
                          .add(ScaleMO)               // Scale
                          .add(IndexMO)               // Index
                          .add(OffsetMO)              // Disp/offset
                          .add(SegmentMO)             // Segment reg
                          .addReg(X86::R11D);

    // No need to insert the actual store of the sensitive data. All of
    // the previously inserted insns are all inserted before the store
    // of the sensitive data, so it's already there.
    break;
  }
  case X86::MOV64mr:
  case X86::MOV64mi32: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    // Insert insn to read the contents of destination address into R11
    MachineInstr *MI2 =
        addOffset(BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), X86::R11)
                      .addReg(BaseRegMO.getReg()),
                  OffsetMO);
    // Insert insn to zero out the low 32 bits of r11d
    // TODO: Use EFLAGS hack from MOV8
    BuildMI(MBB, MI, DL, TII->get(X86::AND32ri), Register(X86::R11D))
        .addReg(Register(X86::R11D))
        .addImm(0);

    // Insert insn to move the secret data into the low 8bits of R11
    if (DestRegMO.isImm()) {
      BuildMI(MBB, MI, DL, TII->get(X86::MOV8ri), Register(X86::R11B))
          .addImm(DestRegMO.getImm());
    } else {
      auto SRIByte =
          TRI->getSubRegIndex(MCRegister(X86::RAX), MCRegister(X86::AL));
      auto SRIWord =
          TRI->getSubRegIndex(MCRegister(X86::RAX), MCRegister(X86::AX));
      auto SRIDouble =
          TRI->getSubRegIndex(MCRegister(X86::RAX), MCRegister(X86::EAX));
      //  MI.print(llvm::errs());
      //  llvm::errs() << "\n";
      //  errs() << "SRIByte: " << SRIByte << '\n';
      //  errs() << "SRIWord: " << SRIWord << '\n';
      //  errs() << "SRIDouble: " << SRIDouble << '\n';
      //  errs() << "Subregidx ax of eax: "
      //         << TRI->getSubRegIndex(MCRegister(X86::EAX),
      //                                MCRegister(X86::AX))
      //         << '\n';
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

    // Insert insn to store R11, whose contents is NOT EQUAL to the
    // contents of (BaseRegMO + OffsetMO) or DestRegMO
    auto ProxyStore = BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
                          .addReg(BaseRegMO.getReg()) // Base
                          .add(ScaleMO)               // Scale
                          .add(IndexMO)               // Index
                          .add(OffsetMO)              // Disp/offset
                          .add(SegmentMO)             // Segment reg
                          .addReg(X86::R11);

    // No need to insert the actual store of the sensitive data. All of
    // the previously inserted insns are all inserted before the store
    // of the sensitive data, so it's already there.
    break;
  }
  case X86::MOVAPSmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    auto Load = BuildMI(MBB, MI, DL, TII->get(X86::MOVAPSrm), X86::XMM15)
                    .addReg(BaseRegMO.getReg())
                    .add(ScaleMO) // Scale
                    .add(IndexMO) // Index
                    .add(OffsetMO)
                    .add(SegmentMO);

    auto FFFF = BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
                    .addImm(0xFFFFFFFFFFFFFF);
    auto FirstFFFF =
        BuildMI(MBB, MI, DL, TII->get(X86::MMX_MOVQ64rr), X86::XMM14)
            .addReg(X86::R11);
    auto ZZZZ = BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
                    .addImm(0x00000000000000);
    auto SecondZZZZ = BuildMI(MBB, MI, DL, TII->get(X86::PINSRQrr), X86::XMM14)
                          .addReg(X86::XMM14)
                          .addReg(X86::R11)
                          .addImm(1);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDPSrr), Register(X86::XMM15))
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MMX_PCMPEQWrr), Register(X86::XMM14))
        .addReg(X86::XMM14)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDNPSrr), Register(X86::XMM15))
        .addReg(Register(X86::XMM15))
        .addReg(Register(X86::XMM14));

    auto Store = BuildMI(MBB, MI, DL, TII->get(X86::MOVAPSmr))
                     .add(BaseRegMO)
                     .add(ScaleMO)
                     .add(IndexMO)
                     .add(OffsetMO)
                     .add(SegmentMO)
                     .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVAPSrr), X86::XMM15).add(DestRegMO);

    auto ZZZZ1 = BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
                     .addImm(0x00000000000000);
    auto FirstZZZZ =
        BuildMI(MBB, MI, DL, TII->get(X86::MMX_MOVQ64rr), X86::XMM14)
            .addReg(X86::R11);
    auto FFFF1 = BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
                     .addImm(0xFFFFFFFFFFFFFF);

    auto SecondFFFF = BuildMI(MBB, MI, DL, TII->get(X86::PINSRQrr), X86::XMM14)
                          .addReg(X86::XMM14)
                          .addReg(X86::R11)
                          .addImm(1);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDPSrr), Register(X86::XMM15))
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MMX_PCMPEQWrr), Register(X86::XMM14))
        .addReg(X86::XMM14)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDNPSrr), Register(X86::XMM15))
        .addReg(Register(X86::XMM15))
        .addReg(Register(X86::XMM14));

    auto OR1 = BuildMI(MBB, MI, DL, TII->get(X86::ORPSrm), X86::XMM15)
                   .addReg(X86::XMM15)
                   .add(BaseRegMO)
                   .add(ScaleMO)
                   .add(IndexMO)
                   .add(OffsetMO)
                   .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVAPSmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::MOVUPSmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    auto Load = BuildMI(MBB, MI, DL, TII->get(X86::MOVUPSrm), X86::XMM15)
                    .addReg(BaseRegMO.getReg())
                    .add(ScaleMO) // Scale
                    .add(IndexMO) // Index
                    .add(OffsetMO)
                    .add(SegmentMO);

    auto FFFF = BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
                    .addImm(0xFFFFFFFFFFFFFF);
    auto FirstFFFF =
        BuildMI(MBB, MI, DL, TII->get(X86::MMX_MOVQ64rr), X86::XMM14)
            .addReg(X86::R11);
    auto ZZZZ = BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
                    .addImm(0x00000000000000);
    auto SecondZZZZ = BuildMI(MBB, MI, DL, TII->get(X86::PINSRQrr), X86::XMM14)
                          .addReg(X86::XMM14)
                          .addReg(X86::R11)
                          .addImm(1);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDPSrr), Register(X86::XMM15))
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MMX_PCMPEQWrr), Register(X86::XMM14))
        .addReg(X86::XMM14)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDNPSrr), Register(X86::XMM15))
        .addReg(Register(X86::XMM15))
        .addReg(Register(X86::XMM14));

    auto Store = BuildMI(MBB, MI, DL, TII->get(X86::MOVUPSmr))
                     .add(BaseRegMO)
                     .add(ScaleMO)
                     .add(IndexMO)
                     .add(OffsetMO)
                     .add(SegmentMO)
                     .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVUPSrr), X86::XMM15).add(DestRegMO);

    auto ZZZZ1 = BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
                     .addImm(0x00000000000000);
    auto FirstZZZZ =
        BuildMI(MBB, MI, DL, TII->get(X86::MMX_MOVQ64rr), X86::XMM14)
            .addReg(X86::R11);
    auto FFFF1 = BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
                     .addImm(0xFFFFFFFFFFFFFF);

    auto SecondFFFF = BuildMI(MBB, MI, DL, TII->get(X86::PINSRQrr), X86::XMM14)
                          .addReg(X86::XMM14)
                          .addReg(X86::R11)
                          .addImm(1);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDPSrr), Register(X86::XMM15))
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MMX_PCMPEQWrr), Register(X86::XMM14))
        .addReg(X86::XMM14)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDNPSrr), Register(X86::XMM15))
        .addReg(Register(X86::XMM15))
        .addReg(Register(X86::XMM14));

    BuildMI(MBB, MI, DL, TII->get(X86::MOVUPSrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    // TODO: Find why ORPSrm gave seg fault
    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVUPSmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::MOVDQAmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQArm), X86::XMM15)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
        .addImm(0xFFFFFFFFFFFFFF);
    BuildMI(MBB, MI, DL, TII->get(X86::MMX_MOVQ64rr), X86::XMM14)
        .addReg(X86::R11);
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
        .addImm(0x00000000000000);
    BuildMI(MBB, MI, DL, TII->get(X86::PINSRQrr), X86::XMM14)
        .addReg(X86::XMM14)
        .addReg(X86::R11)
        .addImm(1);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDPSrr), Register(X86::XMM15))
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MMX_PCMPEQWrr), Register(X86::XMM14))
        .addReg(X86::XMM14)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDNPSrr), Register(X86::XMM15))
        .addReg(Register(X86::XMM15))
        .addReg(Register(X86::XMM14));

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQAmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQArr), X86::XMM15).add(DestRegMO);

    BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
        .addImm(0x00000000000000);
    BuildMI(MBB, MI, DL, TII->get(X86::MMX_MOVQ64rr), X86::XMM14)
        .addReg(X86::R11);
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
        .addImm(0xFFFFFFFFFFFFFF);

    BuildMI(MBB, MI, DL, TII->get(X86::PINSRQrr), X86::XMM14)
        .addReg(X86::XMM14)
        .addReg(X86::R11)
        .addImm(1);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDPSrr), Register(X86::XMM15))
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MMX_PCMPEQWrr), Register(X86::XMM14))
        .addReg(X86::XMM14)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::ANDNPSrr), Register(X86::XMM15))
        .addReg(Register(X86::XMM15))
        .addReg(Register(X86::XMM14));

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQArm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQAmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  default: {
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

FunctionPass* llvm::createX86_64SilentStoreMitigationPass() {
    return new X86_64SilentStoreMitigationPass();
}

INITIALIZE_PASS(X86_64SilentStoreMitigationPass, "ss",
            "Mitigations for silent store optimizations", true, true)

