#include <fstream>
#include <sstream>
#include <string>
#include <cassert>
#include <algorithm>
#include <vector>
#include <set>
#include <map>

#include "MCTargetDesc/X86BaseInfo.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86FrameLowering.h"
#include "X86InstrInfo.h"
#include "X86TargetMachine.h"
#include "X86InstrBuilder.h"
#include "X86.h"
#include "X86MachineFunctionInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"

#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/MC/MCContext.h"

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

static cl::opt<bool> EnableSilentStore("x86-ss",
                        cl::desc("Enable the X86 silent store mitigation."),
                        cl::init(false));

static cl::opt<std::string> SilentStoreCSVPath("x86-ss-csv-path",
                        cl::desc("X86 silent store csv path."),
                        cl::init("test_alert.csv"));

static cl::opt<bool> GenIndex("x86-gen-idx-ss",
                        cl::desc("Generate global indices for silent store instrumentation"),
                        cl::init(false));

namespace {

class X86_64SilentStoreMitigationPass : public MachineFunctionPass {
public:
    static char ID;

    X86_64SilentStoreMitigationPass() : MachineFunctionPass(ID) {}

    bool runOnMachineFunction(MachineFunction &MF) override;

    bool shouldRunOnMachineFunction(const MachineFunction& MF);

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        MachineFunctionPass::getAnalysisUsage(AU);
        AU.setPreservesCFG();
    }

    StringRef getPassName() const override {
        return "Silent stores mitigations";
    }

    bool shouldRunOnInstructionIdx(const std::string& SubName, const int CurIdx) const {
      auto FoundIter = IndicesToInstrument.find(SubName);
      bool SubRequiresInstrumenting = FoundIter != IndicesToInstrument.end();
      assert(SubRequiresInstrumenting &&
             "Trying to instrument sub that doesn't require instrumenting (not "
             "in flagged CSV records)");

      const std::set<int> &Indices = FoundIter->second;
      auto IndicesIter = Indices.find(CurIdx);
      bool IdxRequiresInstrumenting = IndicesIter != Indices.end();

      return IdxRequiresInstrumenting;
    }

private:
    /* The number of instructions coming before this instruction.
     * This is 0 for the first instruction of the function, 1 for the
     * next insn, ... */
    int InstructionIdx{};

    /* Number of instructions instrumented so far. */
    int NumInstrumented{};

    inline static std::map<std::string, std::set<int>> IndicesToInstrument;

    inline static std::map<std::pair<std::string, int>, std::string> ExpectedOpcodeNames;

    inline static std::set<std::string> FunctionsToInstrument;

    inline static std::set<std::string> FunctionsInstrumented;

    inline static bool CSVFileAlreadyParsed{};

    void doX86SilentStoreHardening(MachineInstr& MI, MachineBasicBlock& MBB, MachineFunction& MF, std::vector<MachineInstr*>& Remove);

    struct CheckerAlertCSVLine {
	std::string SubName{};
	std::string OpcodeName{};
	std::string Addr{};
        bool IsSilentStore{};
        bool IsCompSimp{};
        int InsnIdx{};

	void Print() const noexcept {
	    errs() << "CSV ROW:\n";
	    errs() << "\tSubName: " << this->SubName << '\n';
	    errs() << "\tOpcodeName: " << this->OpcodeName << '\n';
	    errs() << "\tAddr: " << this->Addr << '\n';
	    errs() << "\tIsSilentStore: " << this->IsSilentStore << '\n';
	    errs() << "\tIsCompSimp: " << this->IsCompSimp << '\n';
	    errs() << "\tInsnIdx: " << this->InsnIdx << '\n';
	}

        explicit CheckerAlertCSVLine(const std::string& Line) {
            std::istringstream StrReader(Line);

	    // The row so far
            constexpr int NumCols = 13;
            std::vector<std::string> Cols{};

	    // Parser state
	    int ColsRead = 0;
	    std::vector<char> ColChars;
	    bool InQuotedString = false;
	    char CurChar{};
	    bool LineEnded = false;
	    std::string Col{};

	    while (!LineEnded) {
		CurChar = StrReader.get();

		switch (CurChar) {
		case '"':
		    InQuotedString = !InQuotedString;
		    break;
		case '\n':
		case ',':
		case -1:
		    if (InQuotedString) {
			ColChars.push_back(CurChar);
		    } else {
			++ColsRead;

			if (ColChars.size() == 0) {
			    Col = std::string("");
			} else {
			    Col = std::string(ColChars.begin(), ColChars.end());
			}
			
			ColChars.clear();
			Cols.push_back(Col);
			
			if (CurChar == '\n' || CurChar == -1) {
			    LineEnded = true;
			}
		    }
		    break;
		default:
		    ColChars.push_back(CurChar);
		    break;
		}

		if (!StrReader.good()) {
		    if (StrReader.eof()) {
			assert(NumCols == ColsRead && LineEnded &&
			       "Error reading checker alert CSV file, EOF in middle of CSV row");
			break;
		    } else if (StrReader.fail() || StrReader.bad()) {
			assert(false && "Error reading checker alert CSV file, str read failed");
		    }
		}
	    }

	    assert(NumCols == ColsRead && "Checker alert CSV col header mismatch.");

	    constexpr int SubNameColIdx = 0;
	    constexpr int OpcodeNameColIdx = 1;
	    constexpr int AddrColIdx = 2;
	    constexpr int InsnIdxColIdx = 3;
	    constexpr int AlertReasonColIdx = 10;

	    // Parse LLVM MIR opcode name (only used for debugging)
	    const std::string& OpcodeName = Cols.at(OpcodeNameColIdx);
	    this->OpcodeName = OpcodeName;

	    // Parse: is silent store or comp simp?
	    const std::string& AlertReason = Cols.at(AlertReasonColIdx);
	    if (AlertReason == "comp-simp") {
		this->IsCompSimp = true;
	    }

	    if (AlertReason == "silent-stores") {
		this->IsSilentStore = true;
	    }

	    this->Addr = Cols.at(AddrColIdx);

	    // Parse insn idx
	    const std::string& InsnIdxStr = Cols.at(InsnIdxColIdx);
// llvm::errs() << "InsnIdxStr: " << InsnIdxStr << "\n";
        if (!InsnIdxStr.empty()) {
            this->InsnIdx = std::stoi(InsnIdxStr);
        } else {
            llvm::errs() << "Unsupported CSV line: " << Line << "\n";
            this->InsnIdx = -1;
        }

	    // parse fn name
	    this->SubName = Cols.at(SubNameColIdx);
        }
    };

    std::vector<CheckerAlertCSVLine> RelevantCSVLines{};

    void readCheckerAlertCSV(const std::string& Filename);
    bool isRelevantCheckerAlertCSVLine(const CheckerAlertCSVLine& Line);
};
    
} // end anonymous namespace 

/*
 * The CSV file has the following header:
 * harden_silentstore,harden_compsimp,harden_dmp,insn_idx
 */
void X86_64SilentStoreMitigationPass::readCheckerAlertCSV(const std::string& Filename) {
    if (GenIndex) {
        return;
    }

    std::ifstream IFS(Filename);

    if (!IFS.is_open()) {
        errs() << "Couldn't open file " << Filename << " from checker.\n";
        assert(IFS.is_open() && "Couldn't open checker alert csv.\n");
    }

    constexpr size_t MaxLineSize = 1024;
    std::array<char, MaxLineSize> Line{0};
    std::string ExpectedHeader("subroutine_name,"
			       "mir_opcode,"
			       "addr,"
			       "rpo_idx,"
			       "tid,"
			       "problematic_operands,"
			       "left_operand,"
			       "right_operand,"
			       "live_flags,"
			       "is_live,"
			       "alert_reason,"
			       "description,"
                   "flags_live_in");
    bool IsHeader = true;

    // operator bool() on the returned this* from .getline returns 
    // false. i think it returns false when EOF is hit?
    // -1 for null terminator
    while (IFS.getline(Line.data(), MaxLineSize - 1)) {
        std::string CurrentLine(Line.data());

        if (IsHeader) {
            assert(ExpectedHeader == CurrentLine &&
		   "Unexpected header in checker alert csv file");
            IsHeader = false;
        } else {
            CheckerAlertCSVLine CSVLine(CurrentLine);

            if (this->isRelevantCheckerAlertCSVLine(CSVLine)) {
                this->RelevantCSVLines.push_back(CSVLine);
		
		const std::string& SubName = CSVLine.SubName;
		const std::string& OpcodeName = CSVLine.OpcodeName;
		int InsnIdx = CSVLine.InsnIdx;

		FunctionsToInstrument.insert(CSVLine.SubName);

		/* add map of (SubName, InsnIdx) -> ExpectedOpcodeNameString for faster checking later */
		std::pair<std::string, int> NameIdxPair = std::pair<std::string, int>(SubName, InsnIdx);
		auto ExpectedIter = ExpectedOpcodeNames.find(NameIdxPair);
		if (ExpectedIter != ExpectedOpcodeNames.end() &&
		    ExpectedIter->second != OpcodeName) {
		    errs() << "Duplicate subname, idx pair with differing opcodes: "
			   << NameIdxPair.first << ", " << NameIdxPair.second
			   << " differs on opcodes " << ExpectedIter->second << " and " << OpcodeName << '\n';
		    assert(ExpectedIter == ExpectedOpcodeNames.end() &&
			   "Duplicate subname, idx pair in hardening pass");
		}
		ExpectedOpcodeNames.insert({ NameIdxPair, OpcodeName });

		auto IdxIter = IndicesToInstrument.find(SubName);
		if (IdxIter == IndicesToInstrument.end()) {
		    std::set<int> FreshSet{};
		    FreshSet.insert(InsnIdx);
		    IndicesToInstrument[SubName] = FreshSet;
		} else {
		    std::set<int>& Indices = IdxIter->second;
		    Indices.insert(InsnIdx);
		}
            }
        }

	Line.fill(0);
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

bool X86_64SilentStoreMitigationPass::isRelevantCheckerAlertCSVLine(const CheckerAlertCSVLine &Line) {
    return Line.IsSilentStore;
}

void X86_64SilentStoreMitigationPass::doX86SilentStoreHardening(
        MachineInstr& MI, 
        MachineBasicBlock& MBB, 
        MachineFunction& MF,
	std::vector<MachineInstr*>& Remove) {
  DebugLoc DL = MI.getDebugLoc();
  const auto &STI = MF.getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF.getRegInfo();

  // create annotation label with temp name
  /* auto TempSym = MF.getContext().createNamedTempSymbol(); */
  /* BuildMI(MBB, MI, DL, TII->get(X86::ANNOTATION_LABEL)).addSym(TempSym); */
  /* BuildMI(MBB, MI, DL, TII->get(X86::EH_LABEL)).addSym(TempSym); */
  // create machine operand metadata
  /* auto *TempSymMO = MF.getContext().createTempSymbolMDNode(TempSym); */
  /* auto *DbgLabel = MBB.getParent()->getSubprogram()->createDebugLocLabel(DL); */
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
  case X86::XOR64mr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &SrcRegMO = MI.getOperand(5);

    Remove.push_back(&MI);

    MCRegister Src = SrcRegMO.getReg().asMCReg();
    MCRegister Src16 = TRI->getSubReg(Src, X86::sub_16bit);

    // load contents of memory into scratch R12
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), X86::R12)
	.addReg(BaseRegMO.getReg())
	.add(ScaleMO)
	.add(IndexMO)
	.add(OffsetMO)
	.add(SegmentMO);

    // do CS xor64 transform
    {
	BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R10)
	    .addImm(1ULL << 16ULL); // 2 ** 16

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), X86::R10W)
	    .addReg(Src16);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16ri), Src16)
	    .addImm(1);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
	    .addImm(1ULL << 16ULL);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	    .addReg(X86::R12W);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16ri), X86::R12W)
	    .addImm(1);

	BuildMI(MBB, MI, DL, TII->get(X86::XOR64rr), X86::R12)
	    .addReg(X86::R12)
	    .addReg(Src);

	BuildMI(MBB, MI, DL, TII->get(X86::XOR64rr), X86::R11)
	    .addReg(X86::R11)
	    .addReg(X86::R10);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), Src16)
	    .addReg(X86::R10W);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), X86::R12W)
	    .addReg(X86::R11W);
    }

    // compute the blinding value
    {
	BuildMI(MBB, MI, DL, TII->get(X86::MOV64rr), X86::R12)
	    .addReg(X86::R10);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV8rm), X86::R10B)
	    .addReg(BaseRegMO.getReg())
	    .add(ScaleMO)
	    .add(IndexMO)
	    .add(OffsetMO)
	    .add(SegmentMO);

	BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), X86::R10)
	    .addReg(X86::R10);
    }

    //blinding store
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
	.addReg(BaseRegMO.getReg())
	.add(ScaleMO)
	.add(IndexMO)
	.add(OffsetMO)
	.add(SegmentMO)
	.addReg(X86::R10);

    // orig store
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
	.addReg(BaseRegMO.getReg())
	.add(ScaleMO)
	.add(IndexMO)
	.add(OffsetMO)
	.add(SegmentMO)
	.addReg(X86::R12);
    
    break;
  }
  case X86::ADD64mr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &SrcRegMO = MI.getOperand(5);

    Remove.push_back(&MI);

    auto Src = SrcRegMO.getReg().asMCReg();
    auto Src16 = TRI->getSubReg(SrcRegMO.getReg(), X86::sub_16bit);
    auto Src8 = TRI->getSubReg(SrcRegMO.getReg(), X86::sub_8bit);

    /* 1. need to load contents of memory into a scratch register 
       2. need to do ADD64 mitigation
       3. need to blinding store
       4. need to do the store of ADD64 result
    */
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), X86::R12)
	.addReg(BaseRegMO.getReg())
	.add(ScaleMO)
	.add(IndexMO)
	.add(OffsetMO)
	.add(SegmentMO);

    // do CS add64rr transform
    {
	BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R10)
	    .addImm(1ULL << 48ULL); // 2 ** 48

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), X86::R10W)
	    .addReg(X86::R12W);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16ri), X86::R12W)
	    .addImm(1);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV64ri), X86::R11)
	    .addImm(1ULL << 48ULL); // 2 ** 48

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	    .addReg(Src16);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16ri), Src16)
	    .addImm(1);

	BuildMI(MBB, MI, DL, TII->get(X86::ROL64ri), X86::R10)
	    .addReg(X86::R10)
	    .addImm(16);

	BuildMI(MBB, MI, DL, TII->get(X86::ROL64ri), X86::R11)
	    .addReg(X86::R11)
	    .addImm(16);

	BuildMI(MBB, MI, DL, TII->get(X86::ROR64ri), X86::R12)
	    .addReg(X86::R12)
	    .addImm(16);

	BuildMI(MBB, MI, DL, TII->get(X86::ROR64ri), Src)
	    .addReg(Src)
	    .addImm(16);

	BuildMI(MBB, MI, DL, TII->get(X86::ADD32rr), X86::R10D)
	    .addReg(X86::R10D)
	    .addReg(X86::R11D);

	BuildMI(MBB, MI, DL, TII->get(X86::ADC64rr), X86::R12)
	    .addReg(X86::R12)
	    .addReg(Src);

	BuildMI(MBB, MI, DL, TII->get(X86::ROR64ri), X86::R11)
	    .addReg(X86::R11)
	    .addImm(16);

	BuildMI(MBB, MI, DL, TII->get(X86::ROL64ri), Src)
	    .addReg(Src)
	    .addImm(16);

	BuildMI(MBB, MI, DL, TII->get(X86::ROR64ri), X86::R10)
	    .addReg(X86::R10)
	    .addImm(16);

	BuildMI(MBB, MI, DL, TII->get(X86::RCL64ri), X86::R12)
	    .addReg(X86::R12)
	    .addImm(16);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), X86::R12W)
	    .addReg(X86::R10W);

	BuildMI(MBB, MI, DL, TII->get(X86::MOV16rr), Src16)
	.addReg(X86::R11W);
    }
	
    // Compute the blinding value
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rr), X86::R10)
	.addReg(X86::R12);
    
    BuildMI(MBB, MI, DL, TII->get(X86::MOV8rm), X86::R10B)
	.addReg(BaseRegMO.getReg())
	.add(ScaleMO)
	.add(IndexMO)
	.add(OffsetMO)
	.add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::NOT64r),  X86::R10)
	.addReg(X86::R10);

    BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
	.addReg(BaseRegMO.getReg())
	.add(ScaleMO)
	.add(IndexMO)
	.add(OffsetMO)
	.add(SegmentMO)
	.addReg(X86::R10);

    BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
	.addReg(BaseRegMO.getReg())
	.add(ScaleMO)
	.add(IndexMO)
	.add(OffsetMO)
	.add(SegmentMO)
	.addReg(X86::R12);

    break;
  }
  case X86::ADD64mi32: {
    MachineOperand& BaseRegMO = MI.getOperand(0);
    MachineOperand& ScaleMO = MI.getOperand(1);
    MachineOperand& IndexMO = MI.getOperand(2);
    MachineOperand& OffsetMO = MI.getOperand(3);
    MachineOperand& SegmentMO = MI.getOperand(4);
    MachineOperand& SrcMO = MI.getOperand(5);

    Remove.push_back(&MI);

    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm))
      .addReg(X86::R12)
      .add(BaseRegMO)
      .add(ScaleMO)
      .add(IndexMO)
      .add(OffsetMO)
      .add(SegmentMO);

    int64_t Imm = SrcMO.getImm();
    Imm = ~Imm + 1;
    // int64_t Imm = 46464;

    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rr), X86::R11)
      .addReg(X86::R12);

    BuildMI(MBB, MI, DL, TII->get(X86::SUB64ri32), X86::R11)
      .addReg(X86::R11)
      .addImm(Imm);

    BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), X86::R12B)
      .addReg(X86::R11B);

    BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), X86::R12)
      .addReg(X86::R12);

    BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
      .add(BaseRegMO)
      .add(ScaleMO)
      .add(IndexMO)
      .add(OffsetMO)
      .add(SegmentMO)
      .addReg(X86::R12);

    BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
      .add(BaseRegMO)
      .add(ScaleMO)
      .add(IndexMO)
      .add(OffsetMO)
      .add(SegmentMO)
      .addReg(X86::R11);
    
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
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(X86::RAX);
    BuildMI(MBB, MI, DL, TII->get(X86::LAHF));

    BuildMI(MBB, MI, DL, TII->get(X86::AND32ri), Register(X86::R11D))
        .addReg(Register(X86::R11D))
        .addImm(0);

    BuildMI(MBB, MI, DL, TII->get(X86::SAHF));
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R10);

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
  case X86::PUSH64i8:
  case X86::PUSH64r: {
    auto &DestRegMO = MI.getOperand(0);

    // Insert insn to read the contents of destination address into R11
    MachineInstr *MI2 = addOffset(
        BuildMI(MBB, MI, DL, TII->get(X86::MOV64rm), X86::R11).addReg(X86::RSP),
        -8);

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
        BuildMI(MBB, MI, DL, TII->get(X86::MOV8rr), Register(X86::R11B))
            .addReg(fixedWidthDestReg);
      }
    }

    // Insert insn to bitwise not all of R11
    BuildMI(MBB, MI, DL, TII->get(X86::NOT64r), Register(X86::R11))
        .addReg(Register(X86::R11));

    // PUSH64r R11
    // MOV R11 to RSP
    // mov r11, [rsp]
    BuildMI(MBB, MI, DL, TII->get(X86::MOV64mr))
        .addReg(X86::RSP) // Base
        .addImm(1)        // Scale
        .addReg(0)        // Index
        .addImm(-8)       // Disp/offset
        .addReg(0)        // Segment reg
        .addReg(X86::R11);

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
  case X86::MOVDQUmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQUrm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQUmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQUrr), X86::XMM15).add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQUrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::MOVDQUmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::VMOVAPSYmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVAPSYrm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVAPSYmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVAPSYrr), X86::XMM15).add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVAPSYrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVAPSYmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::VMOVUPSYmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVUPSYrm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVUPSYmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVUPSYrr), X86::XMM15).add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVUPSYrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVUPSYmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::VMOVDQA64Zmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQA64Zrm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQA64Zmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQA64Zrr), X86::XMM15)
        .add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQA64Zrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQA64Zmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::VMOVDQAYmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQAYrm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQAYmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQAYrr), X86::XMM15).add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQAYrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQAYmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::VMOVDQAmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQArm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQAmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQArr), X86::XMM15).add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQArm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQAmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::VMOVDQU64Zmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQU64Zrm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQU64Zmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQU64Zrr), X86::XMM15)
        .add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQU64Zrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQU64Zmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::VMOVDQUYmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUYrm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUYmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUYrr), X86::XMM15).add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUYrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUYmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::VMOVDQUmr: {
    auto &BaseRegMO = MI.getOperand(0);
    auto &ScaleMO = MI.getOperand(1);
    auto &IndexMO = MI.getOperand(2);
    auto &OffsetMO = MI.getOperand(3);
    auto &SegmentMO = MI.getOperand(4);
    auto &DestRegMO = MI.getOperand(5);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUrm), X86::XMM15)
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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUrr), X86::XMM15).add(DestRegMO);

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

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUrm), X86::XMM14)
        .addReg(BaseRegMO.getReg())
        .add(ScaleMO) // Scale
        .add(IndexMO) // Index
        .add(OffsetMO)
        .add(SegmentMO);

    BuildMI(MBB, MI, DL, TII->get(X86::ORPSrr), X86::XMM15)
        .addReg(X86::XMM15)
        .addReg(X86::XMM14);

    BuildMI(MBB, MI, DL, TII->get(X86::VMOVDQUmr))
        .add(BaseRegMO)
        .add(ScaleMO)
        .add(IndexMO)
        .add(OffsetMO)
        .add(SegmentMO)
        .addReg(X86::XMM15);
    break;
  }
  case X86::INLINEASM: {
    std::string Asm(MI.getOperand(0).getSymbolName());
    std::vector<std::vector<std::string>> Insts;
    std::vector<std::string> Inst;
    std::string temp = "";
    for (int i = 0; i < Asm.size(); i++) {
      if (Asm[i] == '\n') {
        Insts.push_back(Inst);
        Inst.clear();
        continue;
      }
      if (Asm[i] == ' ' && temp.empty()) {
        continue;
      }
      if (Asm[i] == ' ' || Asm[i] == ',') {
        Inst.push_back(temp);
        temp.clear();
        continue;
      }
      temp.push_back(Asm[i]);
    }
    temp = "";
    bool Instrument = false;
    for (auto Inst : Insts) {
      if (false && Inst[0] == "movq" &&
          Inst[2].find("(") != std::string::npos) {
        Instrument = true;
        temp += "movq " + Inst[2] + ", %r11 \n";
        temp += "andl 0, %r11d \n";
        temp += "movq " + Inst[1] + ", %r10 \n";
        temp += "movb %r10b, %r11b \n";
        temp += "notq %r11 \n";
        temp += "movq %r11, " + Inst[2] + " \n";
      }
      temp += Inst[0];
      for (int i = 1; i < Inst.size(); i++) {
        temp.push_back(' ');
        temp += Inst[i];
        if (i == Inst.size() - 1)
          temp.push_back(' ');
        else
          temp.push_back(',');
      }
      temp.push_back('\n');
    }
    if (Instrument)
      MI.getOperand(0).setSymbolName(temp.c_str());
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

static unsigned int changedOpcode = 0;

static void setupTest(MachineFunction &MF) {
  llvm::errs() << "setupTest \t" << MF.getName() << "\n";
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      llvm::errs() << "MI setupTest \t" << MI << "\n";
      
      if (MI.getOpcode() == X86::RET64) {
        MachineBasicBlock *MBB = MI.getParent();
        MachineFunction *MF = MBB->getParent();
        DebugLoc DL = MI.getDebugLoc();
        const auto &STI = MF->getSubtarget();
        auto *TII = STI.getInstrInfo();
        auto *TRI = STI.getRegisterInfo();
        auto &MRI = MF->getRegInfo();

        auto Op = MF->getName().split('_').second.rsplit('_').first;
        llvm::errs() << "Op setupTest \t" << Op << "\n";

	/* insert saves of r10-15 */
	{
	  BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
	    .addReg(X86::R10);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
	    .addReg(X86::R11);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
	    .addReg(X86::R12);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
	    .addReg(X86::R13);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
	    .addReg(X86::R14);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
	    .addReg(X86::R15);
	}

	/* Insert the test insn, the original insn */
	{
	  if (Op == "ADD64mr") {
	    changedOpcode = X86::ADD64mr;
	    BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64mr), X86::RSI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0)
	      .addReg(0)
	      .addReg(X86::RDX);
	  }

	  else if (Op == "XOR64mr") {
	    changedOpcode = X86::XOR64mr;
	    BuildMI(*MBB, &MI, DL, TII->get(X86::XOR64mr), X86::RSI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0)
	      .addReg(0)
	      .addReg(X86::RDX);
	  }

	  else if (Op == "ADD64mi32") {
	    changedOpcode = X86::ADD64mi32;
	    BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64mi32), X86::RSI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0)
	      .addReg(0)
	      .addImm(17);
	  }
	}
	

	/* insert restores of r12-15. pushed r12, r13, r14, 15 */
	{
	  BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r))
	    .addReg(X86::R15);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r))
	    .addReg(X86::R14);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r))
	    .addReg(X86::R13);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r))
	    .addReg(X86::R12);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r))
	    .addReg(X86::R11);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r))
	    .addReg(X86::R10); 
	}

	/* write state into first argument per 
	   implementation-tester.c OutState struct in pandora-eval repo */
	{
	  /*
	    Intel: [base + index*scale + offset] 
	    ATT: offset(base, index, scale)    
	   */
	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x00) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::RAX);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x8) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::RBX);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x10) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::RCX);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x18) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::RDX);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x20) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::RSP);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x28) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::RBP);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x30) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::RSI);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x38) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::RDI);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x40) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::R8);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x48) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::R9);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x50) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::R10);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x58) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::R11);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x60) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::R12);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x68) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::R13);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x70) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::R14);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	    .addReg(X86::RDI) // base reg
	    .addImm(1) // scale (RDI * 1)
	    .addReg(0) // index reg (none)
	    .addImm(0x78) // offset
	    .addReg(0) // segment reg (none)
	    .addReg(X86::R15);
	}
      }
    }
  }
}

bool X86_64SilentStoreMitigationPass::runOnMachineFunction(MachineFunction& MF) {

    std::vector<MachineInstr*> Remove{};
    
  if (!EnableSilentStore)
    return false;

  if (MF.getName().startswith("x86silentstorestest")) {
    setupTest(MF);
    if (MF.getName().contains("_transformed")) {
      std::vector<MachineInstr *> MIs;
      for (auto &MBB : MF) {
        for (auto &MI : MBB) {
	  if (MI.getOpcode() == changedOpcode) {
	      this->doX86SilentStoreHardening(MI, MBB, MF, Remove);
	  }
        }
      }
    }

    llvm::errs() << "Num MIs to remove: " << Remove.size() << '\n';
    for (auto& MI : Remove) {
	llvm::errs() << "Erasing MI from parent: " << *MI << '\n';
	MI->eraseFromParent();
    }
    Remove.clear();
  
    return true;
  }

  /* static class member: don't reparse the CSV file on each MachineFunction
     in the compilation unit */
  if (!CSVFileAlreadyParsed) {
    this->readCheckerAlertCSV(SilentStoreCSVPath);
    CSVFileAlreadyParsed = true;
  }

  bool doesModifyFunction = false;

  if (!GenIndex && !this->shouldRunOnMachineFunction(MF)) {
    return doesModifyFunction;
  }

  // llvm::errs() << "[SilentStore]\n";

  std::string SubName = MF.getName().str();
  // errs() << "Hardening func: " << SubName << '\n';

  bool SameSymbolNameAlreadyInstrumented =
      FunctionsInstrumented.end() != FunctionsInstrumented.find(SubName);
  if (SameSymbolNameAlreadyInstrumented) {
    errs() << "Trying to transform two different functions with identical "
              "symbol names: "
           << SubName << '\n';
    assert(!SameSymbolNameAlreadyInstrumented &&
           "Trying to transform two different functions"
           " with identical symbol names is not allowed");
  }
  FunctionsInstrumented.insert(SubName);

  for (auto &MBB : MF) {
    // llvm::errs() << "Checking basic block " << MBB << "\n";
    for (llvm::MachineBasicBlock::iterator I = MBB.begin(), E = MBB.end();
         I != E; ++I) {
      llvm::MachineInstr &MI = *I;
      DebugLoc DL = MI.getDebugLoc();
      const auto &STI = MF.getSubtarget();
      auto *TII = STI.getInstrInfo();
      
      // llvm::errs() << "Checking instruction " << MI << "\n";

      if (MI.getOpcode() == X86::SBB64ri32) {
        int CurIdx = MI.getOperand(2).getImm();

        // llvm::errs() << "Found SBB64ri32 instruction at index " << CurIdx << "\n";

        if (this->shouldRunOnInstructionIdx(SubName, CurIdx)) {
          I++;
          llvm::MachineInstr &NextMI = *I;

          // llvm::errs() << "Found instruction " << NextMI << "\n";

          std::string CurOpcodeName = TII->getName(NextMI.getOpcode()).str();
          // don't count 'meta' insns like debug info, CFI indicators
          // as instructions in the instruction idx counts
          // we are only on LLVM14, so this is the only descriptor available.
          const MCInstrDesc &MIDesc = NextMI.getDesc();

          // errs() << "hardening insn at idx " << CurIdx
          //        << " the MIR insn is: " << CurOpcodeName
          //        << " the full MI is: " << NextMI << '\n';

          auto CurNameAndInsnIdx = std::pair<std::string, int>(SubName, CurIdx);
          auto Iter = ExpectedOpcodeNames.find(CurNameAndInsnIdx);
          assert(Iter != ExpectedOpcodeNames.end());
          const std::string &ExpectedOpcode = Iter->second;

          // If there was a mismatch, then find the originating checker
          // alert CSV row and print it out compared to this insn.
          if (CurOpcodeName.find(ExpectedOpcode) == std::string::npos) {
            auto IsCurCsvRow = [&](const CheckerAlertCSVLine &Row) {
              return Row.SubName == SubName && CurIdx == Row.InsnIdx;
            };

            auto ErrIter =
                std::find_if(this->RelevantCSVLines.begin(),
                             this->RelevantCSVLines.end(), IsCurCsvRow);
            assert(ErrIter != this->RelevantCSVLines.end());

            errs() << "Mismatch in instruction indices in function " << SubName
                   << '\n';

            assert(false && "Mismatch in instruction indices");
            errs() << "CSV Row was:\n";
            ErrIter->Print();
            // exit(-1);
          }
          this->doX86SilentStoreHardening(NextMI, MBB, MF, Remove);
          doesModifyFunction = true;
        }
      }
    }
  }

  llvm::errs() << "Num MIs to remove: " << Remove.size() << '\n';
  for (auto& MI : Remove) {
      llvm::errs() << "Erasing MI from parent: " << *MI << '\n';
      MI->eraseFromParent();
  }
  
  return doesModifyFunction;
}

bool X86_64SilentStoreMitigationPass::shouldRunOnMachineFunction(const MachineFunction& MF) {
    
    const std::string FuncName = MF.getName().str();

    auto FuncsIter = FunctionsToInstrument.find(FuncName);

    bool FoundFunction = FuncsIter != FunctionsToInstrument.end();

    return FoundFunction;

    // auto IsFlaggedFunc = [&FuncName](const CheckerAlertCSVLine& CsvLine) {
    // 	const std::string& FlaggedName = CsvLine.SubName;
    // 	return FuncName.equals(FlaggedName);
    // };

    // auto Iter = std::find_if(this->RelevantCSVLines.begin(), this->RelevantCSVLines.end(), IsFlaggedFunc);

    // bool FoundFlaggedFuncSameName = Iter != this->RelevantCSVLines.end();
    
    // return FoundFlaggedFuncSameName;
}

// Useful for debugging passes, keep around.
// bool X86_64SilentStoreMitigationPass::shouldRunOnMachineFunction(const MachineFunction& MF) {
//     const Function& F = MF.getFunction();	    

//     for (auto& Arg : F.args()) {
//         if (Arg.hasAttribute(Attribute::Secret)) {
//             return true;
//         }
//     }

//     return false;
// }

char X86_64SilentStoreMitigationPass::ID = 0;

FunctionPass* llvm::createX86_64SilentStoreMitigationPass() {
    return new X86_64SilentStoreMitigationPass();
}

INITIALIZE_PASS(X86_64SilentStoreMitigationPass, "ss",
            "Mitigations for silent store optimizations", true, true)

