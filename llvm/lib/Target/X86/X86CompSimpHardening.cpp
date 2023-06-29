
#include "MCTargetDesc/X86BaseInfo.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
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
#include <fstream>
#include <math.h>
#include <sstream>
#include <string>
#include <cmath>

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

static cl::opt<bool> RecordTestCycleCounts(
    "x86-cs-test-cycle-counts",
    cl::desc("If testing x86 CS,SS passes, also record cycle counts."),
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

  bool shouldRunOnInstructionIdx(const std::string &SubName,
                                 const int CurIdx) const {
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
  inline static bool CSVFileAlreadyParsed{};
  inline static std::map<std::string, std::set<int>> IndicesToInstrument;
  inline static std::map<std::pair<std::string, int>, std::string>
      ExpectedOpcodeNames;
  inline static std::set<std::string> FunctionsToInstrument;
  inline static std::set<std::string> FunctionsInstrumented;

  void doX86CompSimpHardening(MachineInstr *MI, MachineFunction& MF);
  void subFallBack(MachineInstr *MI);
  Register get64BitReg(MachineOperand *MO, const TargetRegisterInfo *TRI);
    void insertSafeOr8riBefore(MachineInstr* MI);
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
    void insertSafeXor32riBefore(MachineInstr* MI);
  void insertSafeXor32ri8Before(MachineInstr *MI);
  void insertSafeXor64Before(MachineInstr *MI);
  void insertSafeXor64rmBefore(MachineInstr *MI);
  void insertSafeXor64mrBefore(MachineInstr *MI);
  void insertSafeAnd8Before(MachineInstr *MI);
    void insertSafeAnd8riBefore(MachineInstr* MI);
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
    void insertSafeShr64r1Before(MachineInstr *MI);
  void insertSafeShr64riBefore(MachineInstr *MI);
  void insertSafeShr32riBefore(MachineInstr *MI);
  void insertSafeShr32r1Before(MachineInstr *MI);
  void insertSafeSar8riBefore(MachineInstr *MI);
  void insertSafeAnd16Before(MachineInstr *MI);
  void insertSafeAnd32Before(MachineInstr *MI);
  void insertSafeTest32Before(MachineInstr *MI);
  void insertSafeAnd32riBefore(MachineInstr *MI);
  void insertSafeAnd32ri8Before(MachineInstr *MI);
    void insertSafeAnd64rmBefore(MachineInstr* MI);
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
    void insertSafeAdd8rmBefore(MachineInstr *MI);
  void insertSafeAdd8riBefore(MachineInstr *MI);
  void insertSafeAdd16Before(MachineInstr *MI);
  void insertSafeAdd32Before(MachineInstr *MI);
  void insertSafeAdd32rmBefore(MachineInstr *MI);
  void insertSafeAdd32ri8Before(MachineInstr *MI);
  void insertSafeAdc32mi8Before(MachineInstr *MI);
  void insertSafeAdd32ri32Before(MachineInstr *MI);
    void insertSafeAdd32riBefore(MachineInstr *MI);
  void insertSafeAdd32OldBefore(MachineInstr *MI);
  void insertSafeAdd64Before(MachineInstr *MI);
  void insertSafeAdd64rmBefore(MachineInstr *MI);
  void insertSafeAdd64mrBefore(MachineInstr *MI);
  void insertSafeAdc64mrBefore(MachineInstr *MI);
  void insertSafeLea64rBefore(MachineInstr *MI);
  void insertSafeAdd64ri8Before(MachineInstr *MI);
  void insertSafeAdc64ri8Before(MachineInstr *MI);
  void insertSafeAdd64ri32Before(MachineInstr *MI);
  void insertSafeAdd64mi32Before(MachineInstr *MI);
  void insertSafeAdd64mi8Before(MachineInstr *MI);
  void insertSafeShr64Before(MachineInstr *MI);
  void insertSafeShr32Before(MachineInstr *MI);
  void insertSafeAdc64Before(MachineInstr *MI);
  void insertSafeAdc64rmBefore(MachineInstr *MI);
    void insertSafeMul64rBefore(MachineInstr *MI);
  void insertSafeMul32rBefore(MachineInstr *MI);
  void insertSafeIMul32rrBefore(MachineInstr *MI);
  void insertSafeIMul32rmBefore(MachineInstr *MI);
  void insertSafeIMul64rrBefore(MachineInstr *MI);
  void insertSafeIMul64rri8Before(MachineInstr *MI);
  void insertSafeIMul64rri32Before(MachineInstr *MI);
  void insertSafeCmp64rrBefore(MachineInstr *MI);
  void insertSafeCmp32rrBefore(MachineInstr *MI);
  void insertSafeCmp32mrBefore(MachineInstr *MI);
  void insertSafeCmp32rmBefore(MachineInstr *MI);
  void insertSafeCmp64rmBefore(MachineInstr *MI);
    void insertSafeCmp64mrBefore(MachineInstr *MI);
  void insertSafeCmp8rrBefore(MachineInstr *MI);
  void insertSafeVPXorrrBefore(MachineInstr *MI);
  void insertSafeVPOrrrBefore(MachineInstr *MI);
  void insertSafeVPAndrrBefore(MachineInstr *MI);
  void insertSafeVPAndrmBefore(MachineInstr *MI);
  void insertSafeVPOrrmBefore(MachineInstr *MI);
  void insertSafeVPAddDrrBefore(MachineInstr *MI);
    void insertSafePADDDrrBefore(MachineInstr* MI);
    void insertSafePADDQBefore(MachineInstr* MI);
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
  void insertSafeVPShufBrrBefore(MachineInstr *MI);
  void insertSafeVPShufBYrrBefore(MachineInstr *MI);
  void insertSafeVPShufBYrmBefore(MachineInstr *MI);
  void insertSafeAdd64RR(MachineInstr *MI, MachineOperand *Op1,
                         MachineOperand *Op2);
  void readCheckerAlertCSV(const std::string &Filename);
  
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

    explicit CheckerAlertCSVLine(const std::string &Line) {
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
                   "Error reading checker alert CSV file, EOF in middle of CSV "
                   "row");
            break;
          } else if (StrReader.fail() || StrReader.bad()) {
            assert(false &&
                   "Error reading checker alert CSV file, str read failed");
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
      const std::string &OpcodeName = Cols.at(OpcodeNameColIdx);
      this->OpcodeName = OpcodeName;

      // Parse: is silent store or comp simp?
      const std::string &AlertReason = Cols.at(AlertReasonColIdx);
      if (AlertReason == "comp-simp") {
        this->IsCompSimp = true;
      }

      if (AlertReason == "silent-stores") {
        this->IsSilentStore = true;
      }

      this->Addr = Cols.at(AddrColIdx);

      // Parse insn idx
      const std::string &InsnIdxStr = Cols.at(InsnIdxColIdx);
      /* llvm::errs() << "InsnIdxStr: " << InsnIdxStr << "\n"; */
      if (!InsnIdxStr.empty()) {
        this->InsnIdx = std::stoi(InsnIdxStr);
      } else {
        /* llvm::errs() << "Unsupported CSV line: " << Line << "\n"; */
        this->InsnIdx = -1;
      }

      // parse fn name
      this->SubName = Cols.at(SubNameColIdx);
    }
  };
  bool isRelevantCheckerAlertCSVLine(const CheckerAlertCSVLine &Line);
  std::vector<CheckerAlertCSVLine> RelevantCSVLines{};
};
} // end anonymous namespace

bool X86_64CompSimpMitigationPass::isRelevantCheckerAlertCSVLine(
    const CheckerAlertCSVLine &Line) {
  return Line.IsCompSimp;
}

/*
 * The CSV file has the following header:
 * harden_silentstore,harden_compsimp,harden_dmp,insn_idx
 */
void X86_64CompSimpMitigationPass::readCheckerAlertCSV(
    const std::string &Filename) {

  std::ifstream IFS(Filename);

  if (!IFS.is_open()) {
    /* errs() << "Couldn't open file " << Filename << " from checker.\n"; */
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

        const std::string &SubName = CSVLine.SubName;
        const std::string &OpcodeName = CSVLine.OpcodeName;
        int InsnIdx = CSVLine.InsnIdx;

        FunctionsToInstrument.insert(CSVLine.SubName);

        /* add map of (SubName, InsnIdx) -> ExpectedOpcodeNameString for faster
         * checking later */
        std::pair<std::string, int> NameIdxPair =
            std::pair<std::string, int>(SubName, InsnIdx);
        auto ExpectedIter = ExpectedOpcodeNames.find(NameIdxPair);
        if (ExpectedIter != ExpectedOpcodeNames.end() &&
            ExpectedIter->second != OpcodeName) {
          errs() << "Duplicate subname, idx pair with differing opcodes: "
                 << NameIdxPair.first << ", " << NameIdxPair.second
                 << " differs on opcodes " << ExpectedIter->second << " and "
                 << OpcodeName << '\n';
          /* assert(ExpectedIter == ExpectedOpcodeNames.end() && */
          /*        "Duplicate subname, idx pair in hardening pass"); */
        }
        ExpectedOpcodeNames.insert({NameIdxPair, OpcodeName});

        auto IdxIter = IndicesToInstrument.find(SubName);
        if (IdxIter == IndicesToInstrument.end()) {
          std::set<int> FreshSet{};
          FreshSet.insert(InsnIdx);
          IndicesToInstrument[SubName] = FreshSet;
        } else {
          std::set<int> &Indices = IdxIter->second;
          Indices.insert(InsnIdx);
        }
      }
    }

    Line.fill(0);
  }
}

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

void X86_64CompSimpMitigationPass::insertSafeVPShufBrrBefore(MachineInstr *MI) {
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

  // Move a 64-bit non zero contant to R11
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(0xFFFFFFFFFFFFFFFF);

  // Move R11 to XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOV64toPQIZrr), X86::XMM13).addReg(X86::R11);

  // Shift XMM13 left by 64 bits
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSLLDQri), X86::XMM13)
      .addReg(X86::XMM13)
      .addImm(8);

  // Move R11 rto XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOV64toPQIZrr), X86::XMM12).addReg(X86::R11);

  // OR XMM12 and XMM13 and store in XMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM13)
      .addReg(X86::XMM12)
      .addReg(X86::XMM13);

  // XOR XMM12 and XMM12 and store in XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORrr), X86::XMM12)
      .addReg(X86::XMM12)
      .addReg(X86::XMM12);

  // Compare XMM14 and XMM12 and store in XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQQrr), X86::XMM12)
      .addReg(X86::XMM12)
      .addReg(X86::XMM14);

  // AND XMM12 and XMM13 and store in XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPANDrr), X86::XMM12)
      .addReg(X86::XMM12)
      .addReg(X86::XMM13);

  // OR XMM12 and XMM14 and store in XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORrr), X86::XMM12)
      .addReg(X86::XMM12)
      .addReg(X86::XMM14);

  // Shuffle XMM15 with mask XMM12 and store in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSHUFBrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM12);

  // XOR XMM12 and XMM12 and store in XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORrr), X86::XMM12)
      .addReg(X86::XMM12)
      .addReg(X86::XMM12);

  // Compare XMM14 and XMM12 and store in XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQQrr), X86::XMM12)
      .addReg(X86::XMM12)
      .addReg(X86::XMM14);

  // Blend XMM15 and MOp1 with mask XMM12 and store in XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDVBrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(MOp1)
      .addReg(X86::XMM12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM15);
}

void X86_64CompSimpMitigationPass::insertSafeVPShufBYrmBefore(MachineInstr *MI) {
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrm), X86::XMM14)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);
  
  auto MOp2 = X86::YMM14;

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), X86::YMM15).addReg(MOp1);

  // Move a 64-bit non zero contant to R11
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(0xFFFFFFFFFFFFFFFF);

  // Move R11 to XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOV64toPQIZrr), X86::XMM12).addReg(X86::R11);

  // Broadcast XMM12 to YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBROADCASTBYrr), X86::YMM13)
      .addReg(X86::XMM12);

  // XOR YMM12 and YMM12 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM12);

  // Compare YMM14 and YMM12 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQQYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM14);

  // AND YMM12 and YMM13 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPANDYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM13);

  // OR YMM12 and YMM14 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM14);

  // Shuffle YMM15 with mask YMM12 and store in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSHUFBYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM12);

  // XOR YMM12 and YMM12 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM12);

  // Compare YMM14 and YMM12 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQQYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM14);

  // Blend YMM15 and MOp1 with mask YMM12 and store in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDVBYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(MOp1)
      .addReg(X86::YMM12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM15);
}

void X86_64CompSimpMitigationPass::insertSafeVPShufBYrrBefore(MachineInstr *MI) {
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

  // Move a 64-bit non zero contant to R11
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(0xFFFFFFFFFFFFFFFF);

  // Move R11 to XMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOV64toPQIZrr), X86::XMM12).addReg(X86::R11);

  // Broadcast XMM12 to YMM13
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBROADCASTBYrr), X86::YMM13)
      .addReg(X86::XMM12);

  // XOR YMM12 and YMM12 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM12);

  // Compare YMM14 and YMM12 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQQYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM14);

  // AND YMM12 and YMM13 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPANDYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM13);

  // OR YMM12 and YMM14 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPORYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM14);

  // Shuffle YMM15 with mask YMM12 and store in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPSHUFBYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(X86::YMM12);

  // XOR YMM12 and YMM12 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPXORYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM12);

  // Compare YMM14 and YMM12 and store in YMM12
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPCMPEQQYrr), X86::YMM12)
      .addReg(X86::YMM12)
      .addReg(X86::YMM14);

  // Blend YMM15 and MOp1 with mask YMM12 and store in YMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDVBYrr), X86::YMM15)
      .addReg(X86::YMM15)
      .addReg(MOp1)
      .addReg(X86::YMM12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::VMOVDQAYrr), MOp0).addReg(X86::YMM15);
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

void X86_64CompSimpMitigationPass::insertSafeVPAndrmBefore(MachineInstr *MI) {
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPANDrr), X86::XMM13)
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPANDrr), X86::XMM15)
      .addReg(X86::XMM15)
      .addReg(X86::XMM14);

  // Build result by interchanging upper and lower halves of XMM13 and XMM15
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPBLENDWrri), X86::XMM13)
      .addReg(X86::XMM13)
      .addReg(X86::XMM15)
      .addImm(0x0F);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), MOp0).addReg(X86::XMM13);
}

void X86_64CompSimpMitigationPass::insertSafeVPAndrrBefore(MachineInstr *MI) {
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPANDrr), X86::XMM13)
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::VPANDrr), X86::XMM15)
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

void
X86_64CompSimpMitigationPass::insertSafePADDQBefore(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    // definitely SSE2 since MMX reg PADDD has its own MIR opcode:
    // X86::MMX_PADDDrr
    MCRegister Dst128 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Src128;
    MCRegister Scratch128 = X86::XMM15;

    if (X86::PADDQrr == MI->getOpcode()) {
	Src128 = MI->getOperand(2).getReg().asMCReg();
    } else {
	assert(X86::PADDQrm == MI->getOpcode());
	auto Base = MI->getOperand(2);
	auto Scale = MI->getOperand(3);
	auto Index = MI->getOperand(4);
	auto Offset = MI->getOperand(5);
	auto Segment = MI->getOperand(6);
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQUrm), X86::XMM14)
	    .add(Base)
	    .add(Scale)
	    .add(Index)
	    .add(Offset)
	    .add(Segment);
	Src128 = X86::XMM14;
    }

    int NumLanes = 128 / 64;
    for (int LaneIdx = 0; LaneIdx < NumLanes; ++LaneIdx) {
	// r10 := $dst:[63+64*LaneIdx : 64*LaneIdx]
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D)
		.addImm(1ull << 16ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R10W)
		.addReg(Dst128)
		.addImm(3 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R11W)
		.addReg(Dst128)
		.addImm(2 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
		.addReg(X86::R11W);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R11W)
		.addReg(Dst128)
		.addImm(1 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
		.addReg(X86::R11W);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R11W)
		.addReg(Dst128)
		.addImm(0 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
		.addReg(X86::R11W);
	}

	// r11 := $src:[63+64*LaneIdx : 64*LaneIdx]
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R12D)
		.addImm(1ull << 16ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R12W)
		.addReg(Src128)
		.addImm(3 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R13W)
		.addReg(Src128)
		.addImm(2 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W)
		.addReg(X86::R13W);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R13W)
		.addReg(Src128)
		.addImm(1 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W)
		.addReg(X86::R13W);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R13W)
		.addReg(Src128)
		.addImm(0 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W)
		.addReg(X86::R13W);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11)
		.addReg(X86::R12);
		    
	}

	// do 64 bit CS-safe add
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R12D)
		.addImm(1ull << 16ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R13D)
		.addImm(1ull << 16ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W)
		.addReg(X86::R10W);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R13W)
		.addReg(X86::R11W);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::R10W)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::R11W)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R13)
		.addReg(X86::R13)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
		.addReg(X86::R11)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R12D)
		.addReg(X86::R12D)
		.addReg(X86::R13D);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), X86::R10)
		.addReg(X86::R10)
		.addReg(X86::R11);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R13)
		.addReg(X86::R13)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
		.addReg(X86::R11)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
		.addReg(X86::R12W);
	}

	// store 64-bit add result in a scratch vector register
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::PINSRWrr), X86::XMM15)
		.addReg(X86::XMM15)
		.addReg(X86::R10D)
		.addImm(0 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::R10W)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PINSRWrr), X86::XMM15)
		.addReg(X86::XMM15)
		.addReg(X86::R10D)
		.addImm(1 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PINSRWrr), X86::XMM15)
		.addReg(X86::XMM15)
		.addReg(X86::R10D)
		.addImm(2 + 4 * LaneIdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PINSRWrr), X86::XMM15)
		.addReg(X86::XMM15)
		.addReg(X86::R10D)
		.addImm(3 + 4 * LaneIdx);
	}
    }

    // load dst128 with scratch128
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), Dst128)
	.addReg(X86::XMM15);
}

// SSE2
void
X86_64CompSimpMitigationPass::insertSafePADDDrrBefore(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    // definitely SSE2 since MMX reg PADDD has its own MIR opcode:
    // X86::MMX_PADDDrr
    MCRegister Dst128 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Src128;
    
    if (X86::PADDDrm == MI->getOpcode()) {
	auto Base = MI->getOperand(2);
	auto Scale = MI->getOperand(3);
	auto Index = MI->getOperand(4);
	auto Offset = MI->getOperand(5);
	auto Segment = MI->getOperand(6);
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQUrm), X86::XMM14)
	    .add(Base)
	    .add(Scale)
	    .add(Index)
	    .add(Offset)
	    .add(Segment);
	Src128 = X86::XMM14;
    } else {
	assert(X86::PADDDrr == MI->getOpcode());
	Src128 = MI->getOperand(2).getReg().asMCReg();
    }
    

    // // save flags
    // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13)
    // 	.addReg(X86::RAX);
    // BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));
    // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
    // 	.addReg(X86::RAX);
    // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX)
    // 	.addReg(x86::R13);
    // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13)
    // 	.addReg(X86::R10);

    // XMM15 is scratch

    int NumLanes = 128 / 32;
    for (int LaneIdx = 0; LaneIdx < NumLanes; ++LaneIdx) {
	// extract Dst128[LaneIdx*32:LaneIdx*32+31] inclusive into R10W
	// (32-bit GPR dest)
	// same for Src128 into R11W (32-bit GPR src)
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
		.addImm(1ull << 33ull);

	    // should not clear upper DWORD of R10 (2**33 is there)
	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R10D)
		.addReg(Dst128)
		.addImm(LaneIdx * 2 + 1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
		.addReg(X86::R10)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
		.addImm(1ull << 33ull);
	    
	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R11D)
		.addReg(Dst128)
		.addImm(LaneIdx * 2);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R10)
		.addReg(X86::R10)
		.addReg(X86::R11);
	}

	// // load 32bit src operand
	{

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
		.addImm(1ull << 33ull);
	    
	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R11W)
		.addReg(Src128)
		.addImm(LaneIdx * 2 + 1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R11)
		.addReg(X86::R11)
		.addImm(16);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12)
		.addImm(1ull << 33ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PEXTRWrr), X86::R12W)
		.addReg(Src128)
		.addImm(LaneIdx * 2);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R11)
		.addReg(X86::R11)
		.addReg(X86::R12);
	}

	// do 32-bit cs-safe add
	BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R10)
	    .addReg(X86::R10)
	    .addImm(1ull << 31ull);

	BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R10)
	    .addReg(X86::R10)
	    .addImm(1ull << 31ull);

	BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R11)
	    .addReg(X86::R11)
	    .addImm(1ull << 31ull);

	BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R11)
	    .addReg(X86::R11)
	    .addImm(1ull << 31ull);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), X86::R10)
	    .addReg(X86::R10)
	    .addReg(X86::R11);

	BuildMI(*MBB, *MI, DL, TII->get(X86::PINSRWrr), X86::XMM15)
	    .addReg(X86::XMM15)
	    .addReg(X86::R10W)
	    .addImm(LaneIdx * 2);

	BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R10)
	    .addReg(X86::R10)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::PINSRWrr), X86::XMM15)
	    .addReg(X86::XMM15)
	    .addReg(X86::R10W)
	    .addImm(LaneIdx * 2 + 1);
    }

    // move scratch 128-bit SSE register into Dst128
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOVDQArr), Dst128)
	.addReg(X86::XMM15);
		
    // Restore flags
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

void X86_64CompSimpMitigationPass::insertSafeSar8riBefore(MachineInstr *MI) {
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister Dst8 = MI->getOperand(1).getReg().asMCReg();
    int64_t Imm = MI->getOperand(2).getImm();

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ull << 63ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B)
	.addReg(Dst8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(56);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SAR64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(56);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dst8)
	.addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeShr8riBefore(MachineInstr *MI) {
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();


    MCRegister Dst8 = MI->getOperand(1).getReg().asMCReg();

    int64_t Imm = MI->getOperand(2).getImm();

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ull << 63ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B)
	.addReg(Dst8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dst8)
	.addReg(X86::R11B);
}

void X86_64CompSimpMitigationPass::insertSafeShr32r1Before(MachineInstr *MI) {
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister Dst32 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit, &X86::GR64RegClass);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ull << 63ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), Dst64)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);
}

void X86_64CompSimpMitigationPass::insertSafeShr32riBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();

  MCRegister Dst32 = MI->getOperand(1).getReg().asMCReg();
  MCRegister Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit, &X86::GR64RegClass);

  int64_t Imm32 = MI->getOperand(2).getImm();

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
      .addReg(Dst32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
      .addImm(1ull << 63ull);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
      .addReg(Dst64)
      .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), Dst64)
      .addReg(Dst64)
      .addImm(Imm32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
      .addReg(Dst32);
}

void X86_64CompSimpMitigationPass::insertSafeShl64riBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MCRegister Dst64 = MI->getOperand(1).getReg().asMCReg();
  MCRegister Dst16 = TRI->getSubReg(Dst64, X86::sub_16bit);
  MCRegister Dst8 = TRI->getSubReg(Dst64, X86::sub_8bit);
  int64_t Imm = MI->getOperand(2).getImm();

  auto r10 = X86::R10;
  auto r11 = X86::R11;
  auto r11w = X86::R11W;
  auto r11b = X86::R11B;
  auto r12 = X86::R12;
  
  // mask to select only the bottom 6 bits: 0x3F as uint64_t
  int64_t FinalShiftAmount = static_cast<uint64_t>(Imm) % 64;

  // this doesn't work with an imm of 0. hopefully -O2 doesn't
  // use these.
  assert(0 != FinalShiftAmount);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), r10)
    .addImm(1ULL << 63ULL); // 2 ** 63

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), r11)
    .addReg(r10);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), r11w)
    .addReg(Dst16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
    .addImm(1);

  // shift order changes when shift amt > 48, to set CF correctly

  if (FinalShiftAmount <= 48) {
    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), r11)
        .addReg(r11)
        .addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Dst64)
        .addReg(Dst64)
        .addImm(Imm);

  } else {
    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Dst64)
        .addReg(Dst64)
        .addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), r11)
        .addReg(r11)
        .addImm(Imm);
  }

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B)
	.addImm(X86::CondCode::COND_B);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), r10)
    .addReg(r10)
    .addImm(Imm);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), r11)
    .addReg(r11)
    .addReg(r10);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
    .addReg(Dst64)
    .addReg(r11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
    .addReg(Dst64)
    .addReg(r10);

  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), X86::R12)
    .addImm(0);
}

void
X86_64CompSimpMitigationPass::insertSafeShr64r1Before(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister Dst64 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Dst16 = TRI->getSubReg(Dst64, X86::sub_16bit);


    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	.addImm(1ull << 63ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	.addReg(Dst16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R11)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), Dst64)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R10)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64r1), X86::R10)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R10)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R10);
    
}

void X86_64CompSimpMitigationPass::insertSafeShr64riBefore(MachineInstr *MI) {
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister Dst64 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Dst16 = TRI->getSubReg(Dst64, X86::sub_16bit);

    int64_t Imm = MI->getOperand(2).getImm();

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	.addImm(1ull << 63ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	.addReg(Dst16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), Dst64)
	.addReg(Dst64)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R10)
	.addReg(X86::R10)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64r1), X86::R10)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R10)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R10);
}

void X86_64CompSimpMitigationPass::insertSafeSar64riBefore(MachineInstr *MI) {
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister Dst64 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Dst16 = TRI->getSubReg(Dst64, X86::sub_16bit);
    int64_t Imm = MI->getOperand(2).getImm();

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	.addImm(1ull << 63ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	.addReg(Dst16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SAR64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SAR64ri), Dst64)
	.addReg(Dst64)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R10)
	.addReg(X86::R10)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64r1), X86::R10)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64r1), X86::R10)
	.addReg(X86::R10);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R10);
	   
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


  auto Imm = MI->getOperand(2);
  MachineOperand DstMO = MI->getOperand(1);
  assert(DstMO.isReg());
  auto Dst = DstMO.getReg();
  auto Dst64 = TRI->getMatchingSuperReg(Dst, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst)
	  .addReg(Dst);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Dst64)
	  .addReg(Dst64)
	  .addImm(0x4000'0000ULL); /* 2 ** 30 */

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Dst64)
	  .addReg(Dst64)
	  .addImm(0x4000'0000ULL); /* 2 ** 30 */

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Dst64)
	  .addReg(Dst64)
	  .addImm(0x4000'0000ULL); /* 2 ** 30 */

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Dst64)
	  .addReg(Dst64)
	  .addImm(0x4000'0000ULL); /* 2 ** 30 */

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Dst64)
  // 	  .addReg(Dst64)
  // 	  .addImm(pow(2, 31)); /* 2 ** 31 */

  auto ImmVal = Imm.getImm();
  auto ShiftVal = ImmVal % 32;
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Dst64)
	  .addReg(Dst64)
	  .addImm(ShiftVal);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst)
	  .addReg(Dst);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R13B).add(MOp1);

  // auto Op1 = X86::R13B;
  // auto Op2 = MOp2.getReg();

  // auto Op1_64 =
  //     TRI->getMatchingSuperReg(Op1, X86::sub_8bit, &X86::GR64RegClass);
  // auto Op2_64 =
  //     TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D).addImm(pow(2, 31));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B).addReg(Op1);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
  //     .addReg(X86::R10)
  //     .addImm(32 - 5);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R10D).addImm(0x0);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
  //     .addReg(X86::R10D)
  //     .addReg(Op2)
  //     .addImm(4);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
  //     .addReg(Op2_64)
  //     .addImm(pow(2, 31));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op2_64)
  //     .addReg(Op2_64)
  //     .addImm(pow(2, 31));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), Op1)
  //     .addReg(Op1)
  //     .addImm(pow(2, 5) - 1);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Op2_64)
  //     .addReg(Op2_64)
  //     .add(MOp1);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Op2)
  //     .addReg(Op2)
  //     .addReg(X86::R10D)
  //     .addImm(5);
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

  auto EAX = MOp1.getReg();
  auto RAX = TRI->getMatchingSuperReg(EAX, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12).addReg(X86::RCX);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R13).addImm(2147483648);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R13B).addReg(X86::CL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::ECX).addReg(X86::R13D);
  // Move 0 to R13
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R13).addImm(0);
  // Move 0 to R11
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(0);
  // AND RCX with 0x1f
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64ri32), X86::RCX)
      .addReg(X86::RCX)
      .addImm(0x1f);
  // CMP RCX with 0
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri32), X86::RCX).addImm(0);
  // SetZ R11
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R11B).addImm(4);

  // CMOVZ R10D EAX
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
      .addReg(X86::R10D)
      .addReg(EAX)
      .addImm(4);
  // CMOVZ RCX R11
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::RCX)
      .addReg(X86::RCX)
      .addReg(X86::R11)
      .addImm(4);

  // MOV32 EAX EAX
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), EAX).addReg(EAX);

  // SUB RAX 2147483648
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), RAX)
      .addReg(RAX)
      .addImm(2147483648);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), RAX)
      .addReg(RAX)
      .addImm(2147483648);

  // AND CL 31
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND8ri), X86::CL)
      .addReg(X86::CL)
      .addImm(31);

  // SHL64CL RAX
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64rCL), RAX).addReg(RAX);

  // MOV32 EAX EAX
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), EAX).addReg(EAX);

  // CMP R11D with 0
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R11D).addImm(0);

  // CMOVNE EAX R10D
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), EAX)
      .addReg(EAX)
      .addReg(X86::R10D)
      .addImm(5);

  // MOV RCX R12
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RCX).addReg(X86::R12);
}

void X86_64CompSimpMitigationPass::insertSafeShr32rClBefore(MachineInstr *MI) {
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister Dst32 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit, &X86::GR64RegClass);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13)
	.addReg(X86::RCX);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12)
	.addImm(1ull << 31ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R12B)
	.addReg(X86::CL);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::ECX)
	.addReg(X86::R12D);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND64ri8), X86::RCX)
	.addReg(X86::RCX)
	.addImm(0x1F);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), X86::RCX)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B)
	.addImm(X86::CondCode::COND_E);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), X86::R10D)
	.addReg(X86::R10D)
	.addReg(Dst32)
	.addImm(X86::CondCode::COND_E);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::RCX)
	.addReg(X86::RCX)
	.addReg(X86::R12)
	.addImm(X86::CondCode::COND_E);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ull << 63ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND32ri), X86::ECX)
	.addReg(X86::ECX)
	.addImm(31);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64rCL), Dst64)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV32rr), Dst32)
	.addReg(Dst32)
	.addReg(X86::R10D)
	.addImm(X86::CondCode::COND_NE);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RCX)
	.addReg(X86::R13);
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

  auto Op2_32 = TRI->getSubReg(Op2_64, X86::sub_32bit);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(X86::RCX);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12)
      .addImm(/*pow(2, 31)*/ 2147483648);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R12B).addReg(X86::CL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::ECX).addReg(X86::R12D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(0x0);
  // AND R13 with 0x1F
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64ri32), X86::RCX)
      .addReg(X86::RCX)
      .addImm(0x1F);
  // CMP R13 with 0x0
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri32), X86::RCX).addImm(0x0);
  // SETCC R12B
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R12B).addImm(4);
  // CMOVZ R10 and Op1_64
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(Op1_64)
      .addImm(4);
  // CMOVZ R13 and R12
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), X86::RCX)
      .addReg(X86::RCX)
      .addReg(X86::R12)
      .addImm(4);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
      .addImm(9223372036854775808);
  // MOV R11 and Op1
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B).addReg(Op1);
  // AND R13B with 31
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND32ri), X86::ECX)
      .addReg(X86::ECX)
      .addImm(31);
  // SHLCl R11
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64rCL), X86::R11).addReg(X86::R11);
  // MOV R11 and Op1
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1).addReg(X86::R11B);
  // cmp R12D with 0x0
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), X86::R12D).addImm(0x0);
  // CMOVNE Op1 and R10
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMOV64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R10)
      .addImm(5);
  // MOV R13 to Op1
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RCX).addReg(X86::R13);
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
  MachineOperand& Base = MI->getOperand(0);
  MachineOperand& Scale = MI->getOperand(1);
  MachineOperand& Index = MI->getOperand(2);
  MachineOperand& Disp = MI->getOperand(3);
  MachineOperand& Segment = MI->getOperand(4);
  
  int64_t Imm8 = MI->getOperand(5).getImm();

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10)
      .addImm(1ull << 16ull);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rm), X86::R10B)
      .add(Base)
      .add(Scale)
      .add(Index)
      .add(Disp)
      .add(Segment);

  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64ri8), X86::R10)
      .addReg(X86::R10)
      .addImm(Imm8);
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

    MCRegister Dst8 = MI->getOperand(0).getReg().asMCReg();
    int64_t Imm8 = MI->getOperand(1).getImm();

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10)
	.addImm(1ull << 16ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B)
	.addReg(Dst8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND64ri8), X86::R10)
	.addReg(X86::R10)
	.addImm(Imm8);
}

void X86_64CompSimpMitigationPass::insertSafeAnd8riBefore(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister Dst8 = MI->getOperand(1).getReg().asMCReg();
    int64_t Imm8 = MI->getOperand(2).getImm();

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10)
	.addImm(1ULL << 16ULL);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B)
	.addReg(Dst8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND64ri8), X86::R10)
	.addReg(X86::R10)
	.addImm(Imm8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dst8)
	.addReg(X86::R10B);
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R10).addReg(X86::R10).addReg(X86::R11);
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

  MCRegister Dst8 = MI->getOperand(1).getReg().asMCReg();

  MachineOperand& Base = MI->getOperand(2);
  MachineOperand& Scale = MI->getOperand(3);
  MachineOperand& Idx = MI->getOperand(4);
  MachineOperand& Offset = MI->getOperand(5);
  MachineOperand& Segment = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10)
      .addImm(1ULL << 16ULL);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11)
      .addImm(1ULL << 16ULL);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B)
      .addReg(Dst8);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rm), X86::R11B)
      .add(Base)
      .add(Scale)
      .add(Idx)
      .add(Offset)
      .add(Segment);

  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dst8)
      .addReg(X86::R10B);
  
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10).addReg(X86::R10).addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1).addReg(X86::R10B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op2).addReg(X86::R11B);
}

void
X86_64CompSimpMitigationPass::insertSafeOr8riBefore(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    MCRegister Dst8 = MI->getOperand(1).getReg().asMCReg();
    int64_t Imm8 = MI->getOperand(2).getImm();

    int64_t TwoToTheSixteen = 1ULL << 16ULL;

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10)
	.addImm(TwoToTheSixteen);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B)
	.addReg(Dst8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::OR64ri8), X86::R10)
	.addReg(X86::R10)
	.addImm(Imm8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dst8)
	.addReg(X86::R10B);
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

    MCRegister Dst8 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Src8 = MI->getOperand(2).getReg().asMCReg();

    int64_t TwoToTheSixteen = 1ULL << 16ULL;

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10)
	.addImm(TwoToTheSixteen);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11)
	.addImm(TwoToTheSixteen);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B)
	.addReg(Dst8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B)
	.addReg(Src8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R10)
	.addReg(X86::R10)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dst8)
	.addReg(X86::R10B);
	
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R10).addReg(X86::R10).addReg(X86::R11);
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R10).addReg(X86::R10).addReg(X86::R11);
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), X86::R10).addReg(X86::R10).addReg(X86::R11);
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

  MachineOperand MOp0 = MI->getOperand(0);
  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp6 = MI->getOperand(5);

  assert(MOp6.isReg() && "Op2 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp0).add(MOp1).add(MOp2)
      .add(MOp3).add(MOp4);

  auto Op2 = MOp6.getReg();
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr)).add(MOp0).add(MOp1).add(MOp2).add(MOp3).add(MOp4)
      .addReg(X86::R13);
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
      .add(MOp2)
      .add(MOp3)
      .add(MOp4)
      .add(MOp5)
      .add(MOp6);

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

void
X86_64CompSimpMitigationPass::insertSafeXor32riBefore(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    MCRegister Dst32 = MI->getOperand(1).getReg().asMCReg();
    int64_t Imm32 = MI->getOperand(2).getImm();

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ULL << 33ULL);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10D)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R10)
	.addReg(X86::R10)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64ri32), X86::R10)
	.addReg(X86::R10)
	.addImm(Imm32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(X86::R10D);
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

  auto Dest32 = MOp1.getReg();
  auto Imm = MOp2.getImm();

  auto Dest64 =
      TRI->getMatchingSuperReg(Dest32, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32).addReg(Dest32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 33));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
      .addReg(Dest64)
      .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64ri8), Dest64)
      .addReg(Dest64)
      .addImm(Imm);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32).addReg(Dest32);
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
      .add(MOp2)
      .add(MOp3)
      .add(MOp4)
      .add(MOp5)
      .add(MOp6);

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
   * intel syntax
   * xor op1, op2
   *
   *      ↓
   *
   * movq r10, op1:64
   * movq r12, op2:64
   * movl op2:32, op2:32
   * movl op1:32, op1:32
   * movq r11, 2^33
   * sub  op1:64, r11
   * sub  op2:64, r11
   * xor  op2:64, op1:64
   * movl op2:32, op2:32
   * movq op1:64, r10
   * movq op2:64, r12
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

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10D).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(Op2);


  auto Op2_64 = TRI->getMatchingSuperReg(Op2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 = TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);

  /* R11 := 2 ** 33 */
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(0x2'0000'0000ULL);
  
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op2_64)
      .addReg(Op2_64)
      .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::XOR64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(Op2_64);
  
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op2).addReg(Op2);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op1).addReg(X86::R10);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op2).addReg(X86::R10);
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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
      .add(MOp2)
      .add(MOp3)
      .add(MOp4)
      .add(MOp5)
      .add(MOp6);

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
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R12).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R11W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R12W);

  // Correctly set ZF and clear CF
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op1).addImm(0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CLC));
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R11D).addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(8589934592);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R12);
  BuildMI(*MBB, *MI, DL, TII->get(X86::OR64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
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

  // Move MOp1 to R10 
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10).addReg(MOp1.getReg());

  // Move MOp2 to R13
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(MOp2.getReg());

  auto Op1 = X86::R10;
  auto Op2 = X86::R13;

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
     (define attempt-and32 ; and32
     (list
     (mov-r/m64-r64 r10 rax) ; save rax
     (mov-r/m32-r32 ecx ecx) ; zero top 32 bits of ecx
     (mov-r/m32-r32 eax eax) ; zero top 32 bits of eax
     (mov-r64-imm64 r11 (bv (expt 2 33) 64))
     (sub-r/m64-r64 rax r11)
     (sub-r/m64-r64 rcx r11)
     (and-r/m64-r64 rcx rax) ; perform and
     (mov-r/m32-r32 ecx ecx) ; zero top 32 bits of ecx
     (mov-r/m64-r64 rax r10))) ; restore rax
   */

    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    auto Dst32 = MI->getOperand(0).getReg().asMCReg();
    auto Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit,
					  &X86::GR64RegClass);

    auto Src32 = MI->getOperand(2).getReg().asMCReg();
    auto Src64 = TRI->getMatchingSuperReg(Src32, X86::sub_32bit,
					  &X86::GR64RegClass);

    auto r10 = X86::R10;
    auto r11 = X86::R11;

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), r10)
	.addReg(Src64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32)
	.addReg(Src32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), r11)
	.addImm(1ull << 33ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
	.addReg(Src64)
	.addReg(r11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(r11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Dst64)
	.addReg(Dst64)
	.addReg(Src64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64)
	.addReg(r10);
}

void X86_64CompSimpMitigationPass::insertSafeAnd32riBefore(MachineInstr *MI) {
  /**
     (define attempt-and32-imm8-cf-zf
     (list
     (mov-r/m32-r32 ecx ecx) ; zero top 32 bits of ecx
     (mov-r64-imm64 r11 (bv (expt 2 33) 64))
     (sub-r/m64-r64 rcx r11)
     (and-r/m64-imm8 rcx (comp-simp:imm8)) ; perform and
     (mov-r/m32-r32 ecx ecx) ; zero top 32 bits of ecx
     (cmp-r/m32-imm8 ecx (bv 0 8)) ; set ZF
     (clc) ; clear CF
     ))
   */

    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    auto Dst32 = MI->getOperand(0).getReg().asMCReg();
    auto Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit,
					  &X86::GR64RegClass);
    
    auto Imm32 = MI->getOperand(2).getImm();

    auto r11 = X86::R11;

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), r11)
	.addImm(1ull << 33ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(r11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND64ri32), Dst64)
	.addReg(Dst64)
	.addImm(Imm32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), Dst32)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CLC));
}

void X86_64CompSimpMitigationPass::insertSafeAnd32ri8Before(MachineInstr *MI) {
  /**
     ecx is dst32
     (define attempt-and32-imm8-cf-zf
     (list
     (mov-r/m32-r32 ecx ecx) ; zero top 32 bits of ecx
     (mov-r64-imm64 r11 (bv (expt 2 33) 64))
     (sub-r/m64-r64 rcx r11)
     (and-r/m64-imm8 rcx (comp-simp:imm8)) ; perform and
     (mov-r/m32-r32 ecx ecx) ; zero top 32 bits of ecx
     (cmp-r/m32-imm8 ecx (bv 0 8)) ; set ZF
     (clc) ; clear CF
     ))
   */

    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    auto Dst32 = MI->getOperand(0).getReg().asMCReg();
    auto Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit,
					  &X86::GR64RegClass);
    
    auto Imm32 = MI->getOperand(2).getImm();

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ull << 33ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND64ri8), Dst64)
	.addReg(Dst64)
	.addImm(Imm32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), Dst32)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CLC));
	
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

  // Mov MOp2 to R13
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13).add(MOp2);

  assert(MOp1.isReg() && "Op1 is a reg");

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11).addImm(pow(2, 16));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Op1).addReg(Op1).addReg(Op2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R10W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op2_16).addReg(X86::R11W);
  // cmp Op1, 0
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri32), Op1).addImm(0);
}

void
X86_64CompSimpMitigationPass::insertSafeAnd64rmBefore(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    llvm::errs() << "AND64rm num operands: " << MI->getNumOperands() << '\n';

    MCRegister Dst64 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Dst16 = TRI->getSubReg(Dst64, X86::sub_16bit);
    MCRegister Dst8 = TRI->getSubReg(Dst64, X86::sub_8bit);

    MachineOperand& Base = MI->getOperand(2);
    MachineOperand& Scale = MI->getOperand(3);
    MachineOperand& Index = MI->getOperand(4);
    MachineOperand& Offset = MI->getOperand(5);
    MachineOperand& Segment = MI->getOperand(6);

    // load the memory contents into R12, R12 is now Src64
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R12)
	.add(Base)
	.add(Scale)
	.add(Index)
	.add(Offset)
	.add(Segment);
    
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R10)
	.addImm(1ull << 16ull); // 2**16

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
	.addReg(Dst16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11)
	.addImm(1ull << 16ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	.addReg(X86::R12W);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::R12W)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), Dst64)
	.addReg(Dst64)
	.addReg(X86::R12);

    BuildMI(*MBB, *MI, DL, TII->get(X86::AND64rr), X86::R10)
	.addReg(X86::R10)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Dst16)
	.addReg(X86::R10W);
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

  // copy Op4 to R13
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(Op4);

  Op4 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(MOp1.getReg(), 1);
  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(MOp1.getReg(), 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
      .addImm(281474976710656);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12)
      .addImm(281474976710656);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0x1);

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
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
  // sysexit
  /* BuildMI(*MBB, *MI, DL, TII->get(X86::SYSEXIT)); */
}

void X86_64CompSimpMitigationPass::insertSafeIMul32rmBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MachineOperand &MOp0 = MI->getOperand(0);
  MachineOperand &MOp1 = MI->getOperand(1);
  MachineOperand &MOp2 = MI->getOperand(2);
  MachineOperand &MOp3 = MI->getOperand(3);
  MachineOperand &MOp4 = MI->getOperand(4);
  MachineOperand &MOp5 = MI->getOperand(5);
  MachineOperand &MOp6 = MI->getOperand(6);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R12)
      .add(MOp2)
      .add(MOp3)
      .add(MOp4)
      .add(MOp5)
      .add(MOp6);

  Register Op1 = MI->getOperand(1).getReg();
  auto Op1_64 =
      TRI->getMatchingSuperReg(Op1, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_16 = TRI->getSubReg(Op1_64, 4);
  auto Op1_8 = TRI->getSubReg(Op1_64, 1);

  Register Op2 = X86::R12D;
  Register Op2_64 = X86::R12;

  Register ECX = Op2;
  Register RCX = Op2_64;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R13)
      .addImm(9223372036854775808 /* 2^63 */);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10D).addReg(ECX);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R10)
      .addReg(X86::R10)
      .addReg(X86::R13);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R11D).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
      .addReg(X86::R11)
      .addReg(X86::R13);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Op1_64).addReg(X86::R11);
  // IMUL Op1_64 with R10 and store result in Op1_64
  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R10);
  // // Push RAX to stack
  // BuildMI(*MBB, *MI, DL, TII->get(X86::PUSH64r)).addReg(X86::RAX);
  // // MUL64r X86::R10
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r)).addReg(X86::R10);
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r)).addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R10)
      .addReg(X86::R10)
      .addImm(63);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R10B).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(63);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R11B).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R13B).addReg(Op1_8);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Op1_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R10);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Op1_8).addReg(X86::R13B);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(Op1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Op1).addReg(Op1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::R13W).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::R13)
      .addReg(X86::R13)
      .addImm(32);
}

void X86_64CompSimpMitigationPass::insertSafeIMul32rrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto Dest32 = MI->getOperand(1).getReg();
  auto Src32 = MI->getOperand(2).getReg();

  auto Dest64 = TRI->getMatchingSuperReg(Dest32, X86::sub_32bit, &X86::GR64RegClass);
  auto Src64 = TRI->getMatchingSuperReg(Src32, X86::sub_32bit, &X86::GR64RegClass);

  auto Scratch1_64 = X86::R11;
  auto Scratch2_64 = X86::R10;
  auto Scratch2_32 = X86::R10D;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch1_64).addImm(1ULL << 63ULL);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Scratch2_32).addReg(Src32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Scratch2_64)
    .addReg(Scratch2_64)
    .addReg(Scratch1_64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32).addReg(Dest32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch1_64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch2_64);
  
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32).addReg(Dest32);
}

void X86_64CompSimpMitigationPass::insertSafeIMul64rrBefore(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto Dest64 = MI->getOperand(1).getReg();
  auto Src64 = MI->getOperand(2).getReg();

  auto Dest32 = TRI->getSubReg(Dest64, X86::sub_32bit);
  auto Dest16 = TRI->getSubReg(Dest64, X86::sub_16bit);
  auto Dest8 = TRI->getSubReg(Dest64, X86::sub_8bit);

  auto Src32 = TRI->getSubReg(Src64, X86::sub_32bit);
  auto Src16 = TRI->getSubReg(Src64, X86::sub_16bit);
  auto Src8 = TRI->getSubReg(Src64, X86::sub_8bit);

  auto Scratch1_64 = X86::R10;
  auto Scratch1_32 = X86::R10D;

  auto Scratch2_64 = X86::R11;
  auto Scratch2_32 = X86::R11D;

  auto Scratch3_64 = X86::R13;
  auto Scratch3_8 = X86::R13B;

  auto Scratch4_64 = X86::R12;
  auto Scratch4_8 = X86::R12B;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Scratch1_64).addReg(Src64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Scratch2_64).addReg(Dest64);

  // Calculate first term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch3_64).addImm(1ULL << 63ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32).addReg(Scratch1_32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
    .addReg(Src64)
    .addReg(Scratch3_64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32).addReg(Scratch2_32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch3_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Scratch4_64).addReg(Dest64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rr), Dest64)
    .addReg(Dest64)
    .addReg(Src64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL8ri), Src64)
    .addReg(Src64)
    .addImm(63);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8).addImm(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL8ri), Scratch4_64)
    .addReg(Scratch4_64)
    .addImm(63);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Scratch4_8).addImm(1);
  
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Scratch3_8).addReg(Dest8);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Dest8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(Src64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch4_64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dest8).addReg(Scratch3_8);

  // Save 1st term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Scratch4_64).addReg(Dest64);

  // Calculate 2nd term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch3_64).addImm(1ULL << 63ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32).addReg(Scratch1_32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
    .addReg(Src64)
    .addReg(Scratch3_64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Dest64).addReg(Scratch2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dest16).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Dest64)
    .addReg(Dest64)
    .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dest16).addImm(0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Dest64)
    .addReg(Dest64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rr), Dest64)
    .addReg(Dest64)
    .addReg(Src64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(Src64);
  
  // Add 2nd term to 1st term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Src8).addReg(Scratch4_8);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Scratch4_8).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Dest8).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Scratch4_64)
    .addReg(Scratch4_64)
    .addReg(Dest64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Scratch4_8).addReg(Src8);

  // Calculate 3rd term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch3_64).addImm(1ULL << 63ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64).addReg(Scratch1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
    .addReg(Src64)
    .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16).addImm(0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
    .addReg(Src64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32).addReg(Scratch2_32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch3_64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rr), Src64)
    .addReg(Src64)
    .addReg(Dest64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
    .addReg(Src64)
    .addReg(Dest64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Dest64).addReg(Src64);

  // Combine all three terms
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Src8).addReg(Scratch4_8);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Scratch4_8).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Dest8).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch4_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dest8).addReg(Src8);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64).addReg(Scratch1_64);
}

void X86_64CompSimpMitigationPass::insertSafeIMul64rri8Before(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto Dest64 = MI->getOperand(1).getReg();
  auto Src64 = MI->getOperand(2).getReg();
  int64_t Imm8 = MI->getOperand(3).getImm();

  auto Dest32 = TRI->getSubReg(Dest64, X86::sub_32bit);
  auto Dest8 = TRI->getSubReg(Dest64, X86::sub_8bit);

  auto Src32 = TRI->getSubReg(Src64, X86::sub_32bit);
  auto Src16 = TRI->getSubReg(Src64, X86::sub_16bit);
  auto Src8 = TRI->getSubReg(Src64, X86::sub_8bit);

  auto Scratch1_64 = X86::R10;
  auto Scratch1_32 = X86::R10D;

  auto Scratch2_64 = X86::R11;
  auto Scratch2_8 = X86::R11B;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Scratch1_64).addReg(Src64);

  // Calculate first term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch2_64).addImm(1ULL << 63ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32).addReg(Scratch1_32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
    .addReg(Src64)
    .addReg(Scratch2_64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rri8), Dest64)
    .addReg(Dest64)
    .addReg(Src64)
    .addImm(Imm8);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Scratch2_8).addImm(Imm8);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL8ri), Scratch2_64)
    .addReg(Scratch2_64)
    .addImm(63);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch2_64);

  // Save 1st term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Scratch2_64).addReg(Dest64);

  // Calculate 2nd term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64).addReg(Scratch1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
    .addReg(Src64)
    .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16).addImm(0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
    .addReg(Src64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rri8), Dest64)
    .addReg(Dest64)
    .addReg(Src64)
    .addImm(Imm8);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri8), Dest64)
    .addReg(Dest64)
    .addImm(Imm8);

  // Combine terms

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Src8).addReg(Scratch2_8);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Scratch2_8).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Dest8).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dest8).addReg(Src8);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64).addReg(Scratch1_64);
}

void X86_64CompSimpMitigationPass::insertSafeIMul64rri32Before(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  auto Dest64 = MI->getOperand(1).getReg();
  auto Src64 = MI->getOperand(2).getReg();
  int64_t Imm32 = MI->getOperand(3).getImm();

  auto Dest32 = TRI->getSubReg(Dest64, X86::sub_32bit);
  auto Dest8 = TRI->getSubReg(Dest64, X86::sub_8bit);

  auto Src32 = TRI->getSubReg(Src64, X86::sub_32bit);
  auto Src16 = TRI->getSubReg(Src64, X86::sub_16bit);
  auto Src8 = TRI->getSubReg(Src64, X86::sub_8bit);

  auto Scratch1_64 = X86::R10;
  auto Scratch1_32 = X86::R10D;

  auto Scratch2_64 = X86::R11;
  auto Scratch2_32 = X86::R11D;
  auto Scratch2_8 = X86::R11B;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Scratch1_64).addReg(Src64);

  // Calculate first term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch2_64).addImm(1ULL << 63ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32).addReg(Scratch1_32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
    .addReg(Src64)
    .addReg(Scratch2_64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rri32), Dest64)
    .addReg(Dest64)
    .addReg(Src64)
    .addImm(Imm32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), Scratch2_32).addImm(Imm32);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SHL8ri), Scratch2_64)
    .addReg(Scratch2_64)
    .addImm(63);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch2_64);

  // Save 1st term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Scratch2_64).addReg(Dest64);

  // Calculate 2nd term

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64).addReg(Scratch1_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
    .addReg(Src64)
    .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16).addImm(0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
    .addReg(Src64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::IMUL64rri32), Dest64)
    .addReg(Dest64)
    .addReg(Src64)
    .addImm(Imm32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Dest64)
    .addReg(Dest64)
    .addImm(Imm32);

  // Combine terms

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Src8).addReg(Scratch2_8);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Scratch2_8).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Dest8).addImm(1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dest64)
    .addReg(Dest64)
    .addReg(Scratch2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dest8).addReg(Src8);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64).addReg(Scratch1_64);
}

void
X86_64CompSimpMitigationPass::insertSafeMul64rBefore(MachineInstr *MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister rax = X86::RAX;
    MCRegister eax = X86::EAX;
    MCRegister rdx = X86::RDX;

    MCRegister Src64;
    MCRegister Src32;
    MCRegister Src8;

    int IsMemorySrc = MI->getOpcode() == X86::MUL64m;
    int IsRaxSrc = MI->getOpcode() == X86::MUL64r &&
	X86::RAX == MI->getOperand(0).getReg().asMCReg();
    int ShouldUseRcxAsSrc = IsMemorySrc || IsRaxSrc;

    if (MI->getOpcode() == X86::MUL64r) {
	Src64 = MI->getOperand(0).getReg().asMCReg();
	Src32 = TRI->getSubReg(Src64, X86::sub_32bit);
	Src8 = TRI->getSubReg(Src64, X86::sub_8bit);
    } else if (ShouldUseRcxAsSrc) {
	Src64 = X86::RCX;
	Src32 = X86::ECX;
	Src8 = X86::CL;
    } else {
	assert(0 && "unreachable");
    }

    // save args
    {
	if (ShouldUseRcxAsSrc) {
	    // then SS safe store RCX to stack
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R12)
		.addReg(X86::RSP)
		.addImm(1)
		.addReg(0)
		.addImm(-8)
		.addReg(0);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R12B)
		.addReg(X86::CL);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::NOT64r), X86::R12)
		.addReg(X86::R12);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr))
		.addReg(X86::RSP)
		.addImm(1)
		.addReg(0)
		.addImm(-8)
		.addReg(0)
		.addReg(X86::R12);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::PUSH64r), X86::RCX);
	    
	} else {
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
		.addReg(Src64);
	}

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11)
	    .addReg(rax);
    }

    if (IsMemorySrc) {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::RCX)
	    .add(MI->getOperand(0))
	    .add(MI->getOperand(1))
	    .add(MI->getOperand(2))
	    .add(MI->getOperand(3))
	    .add(MI->getOperand(4));
    }

    if (IsRaxSrc) {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RCX)
	    .addReg(X86::RAX);
    }
    
    // calculate first term
    {
	// prepare args
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), rdx)
		.addImm(1ull << 63ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32)
		.addReg(X86::R10D);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
		.addReg(Src64)
		.addReg(rdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), eax)
		.addReg(X86::R11D);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(rdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
		.addReg(rax);
	}

	// perform safe mul
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r), Src64);
	}

	// revert mask in result
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Src64)
		.addReg(Src64)
		.addImm(63);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(63);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R12B)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::DL)
		.addReg(X86::AL);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL)
		.addImm(2);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::RAX)
		.addReg(X86::RAX)
		.addReg(Src64);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::RAX)
		.addReg(X86::RAX)
		.addReg(X86::R12);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL)
		.addReg(X86::DL);
	}

	// save the result
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13)
		.addReg(rax);
	}
    }

    // calculate 2nd term
    {
	// prepare arguments
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), rdx)
		.addImm(1ull << 63ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32)
		.addReg(X86::R10D);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
		.addReg(Src64)
		.addReg(rdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), rax)
		.addReg(X86::R11);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), rax)
		.addReg(rax)
		.addImm(32);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(rdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
		.addReg(rax);
	}

	// perform safe mul
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r), Src64);
	}

	// revert mask in result
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Src64)
		.addReg(Src64)
		.addImm(63);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(63);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R12B)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::DL)
		.addReg(X86::AL);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL)
		.addImm(2);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(Src64);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(X86::R12);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL)
		.addReg(X86::DL);

	    // safe push (SS push64r of RAX)
	    // r12 is free for scratch here, rax has important data
	    {
		BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm))
		    .addReg(X86::R12)
		    .addReg(X86::RSP)
		    .addImm(1)
		    .addReg(0)
		    .addImm(-8)
		    .addReg(0);

		BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R12B)
		    .addReg(X86::AL);

		BuildMI(*MBB, *MI, DL, TII->get(X86::NOT64r), X86::R12)
		    .addReg(X86::R12);

		BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr))
		    .addReg(X86::RSP)
		    .addImm(1)
		    .addReg(0)
		    .addImm(-8)
		    .addReg(0)
		    .addReg(X86::R12);

		BuildMI(*MBB, *MI, DL, TII->get(X86::PUSH64r), rax);
	    }
	}
    }

    // calculate 3rd term
    {
	// prepare args
	{ 
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), rdx)
		.addImm(1ull << 63ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64)
		.addReg(X86::R10);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), Src64)
		.addReg(Src64)
		.addImm(32);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
		.addReg(Src64)
		.addReg(rdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), eax)
		.addReg(X86::R11D);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(rdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
		.addReg(rax);
	}

	// perform safe mul
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r), Src64);
	}

	// revert mask in result
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Src64)
		.addReg(Src64)
		.addImm(63);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(63);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R12B)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::DL)
		.addReg(X86::AL);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL)
		.addImm(2);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(Src64);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(X86::R12);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL)
		.addReg(X86::DL);

	    // safe push (SS push64r of RAX)
	    // r12 is free for scratch here, rax has important data
	    {
		BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm))
		    .addReg(X86::R12)
		    .addReg(X86::RSP)
		    .addImm(1)
		    .addReg(0)
		    .addImm(-8)
		    .addReg(0);

		BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R12B)
		    .addReg(X86::AL);

		BuildMI(*MBB, *MI, DL, TII->get(X86::NOT64r), X86::R12)
		    .addReg(X86::R12);

		BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr))
		    .addReg(X86::RSP)
		    .addImm(1)
		    .addReg(0)
		    .addImm(-8)
		    .addReg(0)
		    .addReg(X86::R12);

		BuildMI(*MBB, *MI, DL, TII->get(X86::PUSH64r), rax);
	    }
	}
    }

    // calculate 4th term
    {
	// prepare arguments
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), rdx)
		.addImm(1ull << 63ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64)
		.addReg(X86::R10);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), Src64)
		.addReg(Src64)
		.addImm(32);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Src64)
		.addReg(Src64)
		.addReg(rdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), rax)
		.addReg(X86::R11);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), rax)
		.addReg(rax)
		.addImm(32);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(rdx);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
		.addReg(rax);
	}

	// perform safe mul
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MUL64r), Src64);
	}

	// revert mask in result
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Src64)
		.addReg(Src64)
		.addImm(63);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), X86::R12)
		.addReg(X86::R12)
		.addImm(63);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::R12B)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::DL)
		.addReg(X86::AL);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL)
		.addImm(2);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(Src64);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), rax)
		.addReg(rax)
		.addReg(X86::R12);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL)
		.addReg(X86::DL);
	}
    }

    // recombine terms
    {
	// 4th term in rdx
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), rdx)
		.addReg(rax);
	}

	// 1st term in rax
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), rax)
		.addReg(X86::R13);
	}

	// safely add 3rd term
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::POP64r), Src64);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11)
		.addImm(0);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHLD64rri8))
		.addReg(X86::R11, RegState::Define)
		.addReg(X86::R11, RegState::Define)
		.addReg(Src64)
		.addImm(32);
	    
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32)
		.addReg(Src32);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
		.addReg(Src64)
		.addImm(1ull << 31ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
		.addReg(Src64)
		.addImm(1ull << 31ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Src64)
		.addReg(Src64)
		.addImm(32);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R12B)
		.addReg(X86::AL);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), rax)
		.addReg(rax)
		.addReg(Src64);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), rdx)
		.addReg(rdx)
		.addReg(X86::R11);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL)
		.addReg(X86::R12B);
	}

	// safely add top 32 bits to RAX
	{
	    BuildMI(*MBB, *MI, DL, TII->get(X86::POP64r), Src64);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11)
		.addImm(0);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHLD64rri8))
		.addReg(X86::R11, RegState::Define)
		.addReg(X86::R11, RegState::Define)
		.addReg(Src64)
		.addImm(32);
	    
	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32)
		.addReg(Src32);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
		.addReg(Src64)
		.addImm(1ull << 31ull);
	    
	    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
		.addReg(Src64)
		.addImm(1ull << 31ull);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Src64)
		.addReg(Src64)
		.addImm(32);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R12B)
		.addReg(X86::AL);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), X86::AL)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8)
		.addImm(1);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), rax)
		.addReg(rax)
		.addReg(Src64);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), rdx)
		.addReg(rdx)
		.addReg(X86::R11);

	    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::AL)
		.addReg(X86::R12B);
	}
    }

    // restore rcx
    if (ShouldUseRcxAsSrc) {
	BuildMI(*MBB, *MI, DL, TII->get(X86::POP64r), X86::RCX);
    } else {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64)
	    .addReg(X86::R10);
    }
}

void X86_64CompSimpMitigationPass::insertSafeMul32rBefore(MachineInstr *MI) {

   MachineBasicBlock *MBB = MI->getParent();
   MachineFunction *MF = MBB->getParent();
   DebugLoc DL = MI->getDebugLoc();
   const auto &STI = MF->getSubtarget();
   auto *TII = STI.getInstrInfo();
   auto *TRI = STI.getRegisterInfo();
   auto &MRI = MF->getRegInfo();

   MachineOperand &MOp0 = MI->getOperand(0);
   Register ECX = MOp0.getReg();
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

   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::RDX)
       .addImm(9223372036854775808 /* 2^63 */);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R10D).addReg(ECX);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R10)
       .addReg(X86::R10)
       .addReg(X86::RDX);
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
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), X86::R13W).addImm(1);
   BuildMI(*MBB, *MI, DL, TII->get(X86::SHR64ri), X86::RDX)
       .addReg(X86::RDX)
       .addImm(32);
   BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::EAX).addReg(X86::EAX);

   // SYSEXIT
   /* BuildMI(*MBB, *MI, DL, TII->get(X86::SYSEXIT)); */
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);
  MachineOperand MOp3 = MI->getOperand(3);
  MachineOperand MOp4 = MI->getOperand(4);
  MachineOperand MOp5 = MI->getOperand(5);
  MachineOperand MOp6 = MI->getOperand(6);

  assert(MOp1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp2).add(MOp3).add(MOp4).add(MOp5).add(MOp6);

  auto Op3 = MOp1.getReg();
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

  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp3 = MI->getOperand(2);
  MachineOperand MOp4 = MI->getOperand(3);
  MachineOperand MOp5 = MI->getOperand(4);
  MachineOperand MOp6 = MI->getOperand(5);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R14).add(MOp6);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5);

  auto Op3 = X86::R13;
  auto Op4 = X86::R14;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0x1);

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
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr)).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5).addReg(Op3);
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

  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp3 = MI->getOperand(2);
  MachineOperand MOp4 = MI->getOperand(3);
  MachineOperand MOp5 = MI->getOperand(4);
  MachineOperand MOp6 = MI->getOperand(5);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R14).add(MOp6);

  auto Op3 = X86::R13;
  auto Op4 = X86::R14;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);
  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(281474976710656);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(281474976710656);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0x1);

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
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);
 
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr)).add(MOp1).add(MOp2).add(MOp3).add(MOp4).add(MOp5).addReg(Op3);
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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  auto Dest64 = MOp1.getReg();
  auto Dest16 = TRI->getSubReg(Dest64, X86::sub_16bit);

  auto Imm = MOp2.getImm();
  auto Src64 = X86::R12;
  auto Src16 = X86::R12W;
  auto Src8 = X86::R12B;

  auto Scratch1_64 = X86::R10;
  auto Scratch1_32 = X86::R10D;
  auto Scratch1_16 = X86::R10W;

  auto Scratch2_64 = X86::R11;
  auto Scratch2_32 = X86::R11D;
  auto Scratch2_16 = X86::R11W;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Src64).addImm(0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64ri32), Src64)
    .addReg(Src64)
    .addImm(Imm);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch1_64).addImm(1ULL << 48ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Scratch1_16).addReg(Dest16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dest16).addImm(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch2_64).addImm(1ULL << 48ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Scratch2_16).addReg(Src16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16).addImm(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Scratch1_64)
    .addReg(Scratch1_64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Scratch2_64)
    .addReg(Scratch2_64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Dest64)
    .addReg(Dest64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
    .addReg(Src64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R11D)
    .addReg(Scratch1_32)
    .addReg(Scratch2_32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Dest64)
    .addReg(Dest64)
    .addReg(Src64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Scratch2_64)
    .addReg(Scratch2_64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
    .addReg(Src64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Scratch1_64)
    .addReg(Scratch1_64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Dest64)
    .addReg(Dest64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Dest16).addReg(Scratch1_16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Src8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Dest64).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Src8).addImm(0x0);
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op3R).addReg(Op3R).addImm(16);

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

  MachineOperand MOp1 = MI->getOperand(1);
  MachineOperand MOp2 = MI->getOperand(2);

  assert(MOp1.isReg() && "Op1 is a reg");

  auto Dest64 = MOp1.getReg();
  auto Dest16 = TRI->getSubReg(Dest64, X86::sub_16bit);

  auto Imm = MOp2.getImm();
  auto Src64 = X86::R12;
  auto Src16 = X86::R12W;
  auto Src8 = X86::R12B;

  auto Scratch1_64 = X86::R10;
  auto Scratch1_32 = X86::R10D;
  auto Scratch1_16 = X86::R10W;

  auto Scratch2_64 = X86::R11;
  auto Scratch2_32 = X86::R11D;
  auto Scratch2_16 = X86::R11W;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Src64).addImm(0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64ri8), Src64)
    .addReg(Src64)
    .addImm(Imm);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch1_64).addImm(1ULL << 48ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Scratch1_16).addReg(Dest16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dest16).addImm(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch2_64).addImm(1ULL << 48ULL);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Scratch2_16).addReg(Src16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16).addImm(1);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Scratch1_64)
    .addReg(Scratch1_64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Scratch2_64)
    .addReg(Scratch2_64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Dest64)
    .addReg(Dest64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
    .addReg(Src64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R11D)
    .addReg(Scratch1_32)
    .addReg(Scratch2_32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Dest64)
    .addReg(Dest64)
    .addReg(Src64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Scratch2_64)
    .addReg(Scratch2_64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
    .addReg(Src64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Scratch1_64)
    .addReg(Scratch1_64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Dest64)
    .addReg(Dest64)
    .addImm(16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Dest16).addReg(Scratch1_16);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Src8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Dest64).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Src8).addImm(0x0);
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

  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp3 = MI->getOperand(2);
  MachineOperand MOp4 = MI->getOperand(3);
  MachineOperand MOp5 = MI->getOperand(4);
  MachineOperand MOp6 = MI->getOperand(5);

  assert(MOp6.isReg() && "Op6 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
      .add(MOp1)
      .add(MOp2)
      .add(MOp3)
      .add(MOp4)
      .add(MOp5);

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

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr))
      .add(MOp1)
      .add(MOp2)
      .add(MOp3)
      .add(MOp4)
      .add(MOp5)
      .addReg(X86::R13);
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

  MachineOperand MOp1 = MI->getOperand(0);
  MachineOperand MOp2 = MI->getOperand(1);
  MachineOperand MOp3 = MI->getOperand(2);
  MachineOperand MOp4 = MI->getOperand(3);
  MachineOperand MOp5 = MI->getOperand(4);
  MachineOperand MOp6 = MI->getOperand(5);

  assert(MOp6.isReg() && "Op6 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
      .add(MOp1)
      .add(MOp2)
      .add(MOp3)
      .add(MOp4)
      .add(MOp5);

  auto Op4 = MOp6.getReg();
  auto Op3 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(Op3, 1);

  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(Op3, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0x1);

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
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64mr))
      .add(MOp1)
      .add(MOp2)
      .add(MOp3)
      .add(MOp4)
      .add(MOp5)
      .addReg(X86::R13);
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

  MachineOperand Op1 = MI->getOperand(0);
  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  assert(Op1.isReg() && "Op1 is a reg");

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  auto Op7 = Op1.getReg();
  auto Op8 = X86::R13;

  auto Op8_8 = TRI->getSubReg(Op8, 1);
  auto Op7_8 = TRI->getSubReg(Op7, 1);

  auto Op8_16 = TRI->getSubReg(Op8, 4);
  auto Op7_16 = TRI->getSubReg(Op7, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op8_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op8_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(pow(2, 48));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op7_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op7_16).addImm(0x1);

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
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op8R).addReg(Op8R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op7R).addReg(Op7R).addImm(16);

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

  // copy Op4 to R13 
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(Op4);

  Op4 = X86::R13;

  auto Op4_8 = TRI->getSubReg(Op4, 1);
  auto Op3_8 = TRI->getSubReg(MOp1.getReg(), 1);
  auto Op4_16 = TRI->getSubReg(Op4, 4);
  auto Op3_16 = TRI->getSubReg(MOp1.getReg(), 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(281474976710656);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op4_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op4_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R12).addImm(281474976710656);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R12W).addReg(Op3_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op3_16).addImm(0x1);

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
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op4R).addReg(Op4R).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
      .addReg(X86::R11)
      .addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op3R).addReg(Op3R).addImm(16);

  // BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
  // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R12);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op3_16).addReg(X86::R12W);

  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op4_8).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op3).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op4).addImm(0x0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op4_16).addReg(X86::R11W);
  // sysexit
  /* BuildMI(*MBB, *MI, DL, TII->get(X86::SYSEXIT)); */
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

  MCRegister Dst32 = MI->getOperand(0).getReg().asMCReg();
  MachineOperand& Base = MI->getOperand(1);
  MachineOperand& Scale = MI->getOperand(2);
  MachineOperand& Index = MI->getOperand(3);
  MachineOperand& Disp = MI->getOperand(4);
  MachineOperand& Segment = MI->getOperand(5);

  MCRegister Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit, &X86::GR64RegClass);

  MCRegister Src64 = X86::R13;
  MCRegister Src32 = X86::R13D;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rm), X86::R13D)
      .add(Base)
      .add(Scale)
      .add(Index)
      .add(Disp)
      .add(Segment);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11)
	.addReg(Src64);
    
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32)
	.addReg(Src32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
	.addReg(Src64)
	.addImm(1ull << 31ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
	.addReg(Src64)
	.addImm(1ull << 31ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
	.addReg(Src64)
	.addImm(1ull << 31ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
	.addReg(Src64)
	.addImm(1ull << 31ull);
    
    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(Src64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32ri), Dst32)
	.addReg(Dst32)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), X86::R12)
	.addImm(32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Dst64)
	.addReg(X86::R10);
}

void
X86_64CompSimpMitigationPass::insertSafeCmp64mrBefore(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    MachineOperand& Base = MI->getOperand(0);
    MachineOperand& Scale = MI->getOperand(1);
    MachineOperand& Index = MI->getOperand(2);
    MachineOperand& Disp = MI->getOperand(3);
    MachineOperand& Segment = MI->getOperand(4);

    MCRegister Src64 = MI->getOperand(5).getReg().asMCReg();
    MCRegister Src16 = TRI->getSubReg(Src16, X86::sub_16bit);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
	.add(Base)
	.add(Scale)
	.add(Index)
	.add(Disp)
	.add(Segment);

    MCRegister Dst64 = X86::R13;
    MCRegister Dst16 = X86::R13W;

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	.addImm(1ull << 48ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
	.addReg(Dst16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ull << 48ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	.addReg(Src16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R10)
	.addReg(X86::R10)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Dst64)
	.addReg(Dst64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
	.addReg(Src64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32rr), X86::R10D)
	.addReg(X86::R10D)
	.addReg(X86::R11D);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SBB64rr), Dst64)
	.addReg(Dst64)
	.addReg(Src64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
	.addReg(X86::R10)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
	.addReg(Src64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Dst64)
	.addReg(Dst64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Dst16)
	.addReg(X86::R10W);

    // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
    // 	.addReg(X86::RA

    BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R10B)
	.addImm(X86::CondCode::COND_B);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Dst64)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), X86::R10)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Dst64)
	.addReg(X86::R12);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Src16)
	.addReg(X86::R11W);
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

    MCRegister Dst64 = MI->getOperand(0).getReg().asMCReg();
    MCRegister Dst16 = TRI->getSubReg(Dst64, X86::sub_16bit);

    MachineOperand& Base = MI->getOperand(1);
    MachineOperand& Scale = MI->getOperand(2);
    MachineOperand& Index = MI->getOperand(3);
    MachineOperand& Disp = MI->getOperand(4);
    MachineOperand& Segment = MI->getOperand(5);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
	.add(Base)
	.add(Scale)
	.add(Index)
	.add(Disp)
	.add(Segment);

    MCRegister Src64 = X86::R13;
    MCRegister Src16 = X86::R13W;

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	.addImm(1ull << 48ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
	.addReg(Dst16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ull << 48ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	.addReg(Src16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R10)
	.addReg(X86::R10)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Dst64)
	.addReg(Dst64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
	.addReg(Src64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32rr), X86::R10D)
	.addReg(X86::R10D)
	.addReg(X86::R11D);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SBB64rr), Dst64)
	.addReg(Dst64)
	.addReg(Src64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
	.addReg(X86::R10)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
	.addReg(Src64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Dst64)
	.addReg(Dst64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Dst16)
	.addReg(X86::R10W);

    // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
    // 	.addReg(X86::RA

    BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R10B)
	.addImm(X86::CondCode::COND_B);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Dst64)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), X86::R10)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Dst64)
	.addReg(X86::R12);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Src16)
	.addReg(X86::R11W);
  
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

  // MOV MOp2 to R13
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13).addReg(MOp2.getReg());

  auto Op1 = MOp1.getReg();
  auto Op2 = X86::R13;

  auto Op1_16 = TRI->getSubReg(Op1, 4);
  auto Op2_16 = TRI->getSubReg(Op2, 4);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10).addImm(281474976710656);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W).addReg(Op1_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op1_16).addImm(0x1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11).addImm(281474976710656);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W).addReg(Op2_16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Op2_16).addImm(0x1);
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Op2).addReg(Op2).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Op1).addReg(Op1).addImm(16);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Op1_16).addReg(X86::R10W);
  
  BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), Op2_16).addImm(2);
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Op1).addImm(0x0);
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Op2).addImm(0x0);

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

void
X86_64CompSimpMitigationPass::insertSafeAdd32riBefore(MachineInstr *MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    MCRegister Dest32 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Dest64 = TRI->getMatchingSuperReg(Dest32,
						 X86::sub_32bit,
						 &X86::GR64RegClass);

    int32_t Imm = MI->getOperand(2).getImm();

    llvm::errs() << "Dest64 for Add32ri is: " << TRI->getRegAsmName(Dest64) << '\n';

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32)
	.addReg(Dest32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Dest64)
	.addReg(Dest64)
	.addImm(1ULL << 31ULL); // 2**31

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Dest64)
	.addReg(Dest64)
	.addImm(1ULL << 31ULL); // 2**31

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64ri32), Dest64)
	.addReg(Dest64)
	.addImm(Imm);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32)
	.addReg(Dest32);
}

void X86_64CompSimpMitigationPass::insertSafeAdd32ri8Before(MachineInstr *MI) {
  /**
   * add ecx, imm
   *
   *    ↓
   *
   * movl ecx, ecx
   * sub  r13, 2^31 (32-bit)
   * sub  r13, 2^31 (32-bit)
   * sub  r13, 2^31 (32-bit)
   * sub  r13, 2^31 (32-bit)
   * add  rcx, imm
   * bt   rcx, 32 (8-bit)
   * movl ecx, ecx
   */

  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();
  auto &MRI = MF->getRegInfo();

  MCRegister Dest32 = MI->getOperand(1).getReg().asMCReg();
  MCRegister Dest64 = TRI->getMatchingSuperReg(Dest32,
  					 X86::sub_32bit,
  					 &X86::GR64RegClass);

  int8_t Imm = MI->getOperand(2).getImm();   


  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32)
    .addReg(Dest32);       

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
    .addImm(1ULL << 33ULL);
    
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dest64)
    .addReg(Dest64)
    .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri32), X86::R11)
    .addImm(0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32ri8), X86::R11)
    .addReg(X86::R11)
    .addImm(Imm);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dest64)
    .addReg(Dest64)
    .addReg(X86::R11);

  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), Dest32)
    .addImm(0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), Dest64)
    .addImm(32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dest32)
    .addReg(Dest32);
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

  MachineOperand Op0 = MI->getOperand(0);
  MachineOperand Op1 = MI->getOperand(1);
  MachineOperand Op2 = MI->getOperand(2);
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);

  auto I1 = BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R13).add(Op5);
  auto I2 = BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rm), X86::R14).add(Op0).add(Op1).add(Op2).add(Op3).add(Op4);

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
  MachineOperand Op3 = MI->getOperand(3);
  MachineOperand Op4 = MI->getOperand(4);
  MachineOperand Op5 = MI->getOperand(5);
  MachineOperand Op6 = MI->getOperand(6);

  // Copy memory operand to R13
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rm), X86::R13)
      .add(Op2)
      .add(Op3)
      .add(Op4)
      .add(Op5)
      .add(Op6);

  assert(Op1.isReg() && "Op1 is a reg");

  auto R1 = Op1.getReg();
  auto R2 = X86::R13D;

  auto Op2_64 =
      TRI->getMatchingSuperReg(R2, X86::sub_32bit, &X86::GR64RegClass);
  auto Op1_64 =
      TRI->getMatchingSuperReg(R1, X86::sub_32bit, &X86::GR64RegClass);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11).addReg(Op2_64);
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op1_64)
      .addReg(Op1_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op1_64)
      .addReg(Op1_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R11D).addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R11)
      .addReg(X86::R11)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R11)
      .addReg(X86::R11)
      .addImm(pow(2, 31));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);

  // CMP64ri Op1 with 0
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), R1).addImm(0x0);

  // BT64ri R1 with 32
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), R1).addImm(32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
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
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op1_64)
      .addReg(Op1_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Op1_64)
      .addReg(Op1_64)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), X86::R11D).addReg(X86::R11D);
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R11)
      .addReg(X86::R11)
      .addImm(pow(2, 31));
  BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), X86::R11)
      .addReg(X86::R11)
      .addImm(pow(2, 31));

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Op1_64)
      .addReg(Op1_64)
      .addReg(X86::R11);

  // CMP64ri Op1 with 0
  BuildMI(*MBB, *MI, DL, TII->get(X86::CMP32ri8), R1)
      .addImm(0x0);

  // BT64ri R1 with 32
  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), R1)
      .addImm(32);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), R1).addReg(R1);
}

void
X86_64CompSimpMitigationPass::insertSafeAdd8riBefore(MachineInstr* MI)
{
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  DebugLoc DL = MI->getDebugLoc();
  const auto &STI = MF->getSubtarget();
  auto *TII = STI.getInstrInfo();
  auto *TRI = STI.getRegisterInfo();

  auto Dest8 = MI->getOperand(1).getReg();
  auto Dest64 = TRI->getMatchingSuperReg(Dest8, X86::sub_8bit,
                                         &X86::GR64RegClass);

  auto Imm = MI->getOperand(2).getImm();

  auto Src64 = X86::R11;
  auto Src8 = X86::R11B;

  auto Scratch64 = X86::R10;
  auto Scratch8 = X86::R10B;

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Src64).addImm(0);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Src8).addImm(Imm);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Scratch64).addImm(1ull << 31ull);
 
  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Scratch8).addReg(Dest8);

  BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Scratch64)
	.addReg(Scratch64)
	.addReg(Src64);

  BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8))
    .addReg(Scratch64)
    .addImm(8);

  BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dest8)
    .addReg(Scratch8);
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
  /* assert(false && "TODO: debug this to find how to convert cx into ecx"); */
  llvm::errs() << "Unable to convert cx into ecx\n";
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
  /* assert(false && "TODO: debug this to find how to convert cx into ecx"); */
  llvm::errs() << "Not implemented yet\n";
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

void X86_64CompSimpMitigationPass::insertSafeCmp64rrBefore(MachineInstr *MI) {
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();

    MCRegister Dst64 = MI->getOperand(0).getReg().asMCReg();
    MCRegister Src64 = MI->getOperand(1).getReg().asMCReg();

    MCRegister Dst16 = TRI->getSubReg(Dst64, X86::sub_16bit);
    MCRegister Src16 = TRI->getSubReg(Src64, X86::sub_16bit);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	.addImm(1ull << 48ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
	.addReg(Dst16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ull << 48ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	.addReg(Src16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16)
	.addImm(1);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R10)
	.addReg(X86::R10)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Dst64)
	.addReg(Dst64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
	.addReg(Src64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32rr), X86::R10D)
	.addReg(X86::R10D)
	.addReg(X86::R11D);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SBB64rr), Dst64)
	.addReg(Dst64)
	.addReg(Src64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
	.addReg(X86::R10)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
	.addReg(X86::R11)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
	.addReg(Src64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Dst64)
	.addReg(Dst64)
	.addImm(16);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Dst16)
	.addReg(X86::R10W);

    // BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
    // 	.addReg(X86::RA

    BuildMI(*MBB, *MI, DL, TII->get(X86::SETCCr), X86::R10B)
	.addImm(X86::CondCode::COND_B);

    BuildMI(*MBB, *MI, DL, TII->get(X86::CMP64ri8), Dst64)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), X86::R10)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Dst64)
	.addReg(X86::R12);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Src16)
	.addReg(X86::R11W);
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

    MCRegister Dst32 = MI->getOperand(0).getReg().asMCReg();
    MCRegister Src32 = MI->getOperand(1).getReg().asMCReg();

    MCRegister Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit, &X86::GR64RegClass);
    MCRegister Src64 = TRI->getMatchingSuperReg(Src32, X86::sub_32bit, &X86::GR64RegClass);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R11)
	.addReg(Src64);
    
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Src32)
	.addReg(Src32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	.addReg(Dst32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
	.addReg(Src64)
	.addImm(1ull << 31ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
	.addReg(Src64)
	.addImm(1ull << 31ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
	.addReg(Src64)
	.addImm(1ull << 31ull);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64ri32), Src64)
	.addReg(Src64)
	.addImm(1ull << 31ull);
    
    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	.addReg(Dst64)
	.addReg(Src64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R12)
	.addReg(Dst64);

    BuildMI(*MBB, *MI, DL, TII->get(X86::SUB32ri), Dst32)
	.addReg(Dst32)
	.addImm(0);

    BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8), X86::R12)
	.addImm(32);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Src64)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Dst64)
	.addReg(X86::R10);
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

    MCRegister Dst8 = MI->getOperand(1).getReg().asMCReg();
    MCRegister Src8 = MI->getOperand(2).getReg().asMCReg();

    // Load Src8 into R10B with high bit set
    {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32ri), X86::R10D)
	    .addImm(1ULL << 30ULL);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B)
	    .addReg(Src8);
    }

    // Load Dst8 into R11B
    {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B)
	    .addReg(Dst8);
    }

    // do the sub
    {
	BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), X86::R11)
	    .addReg(X86::R11)
	    .addReg(X86::R10);
    }

    // mov the result into Dst8
    {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dst8)
	    .addReg(X86::R11B);
    }
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

void
X86_64CompSimpMitigationPass::insertSafeLea64rBefore(MachineInstr *MI)
{
  /*
    LEA64r: 
    - in intel syntax: lea $DST:64, [base + idx*scale + offset]
    - in GAS syntax: lea offset(base, idx, scale), $DST:64

    notes:
    - LEA64r needs to preserve CF for libsodium
    - some references call offset displacement
    - base and  idx are registers
    - offset and scale  are immediates  (compile timknown e constants)
    - scale is one of {1, 2, 4, 8}
    - i believe that base is mandatory, but the others are optional
    - offset is either  an 8, 16, or 32 bit value
    - details on this addressing mode (this data) in Section 3.7.5 intel SDM
    - seems like IndexMO.getReg().isPhysical() && IndexMO.getReg().isValid() iff IndexMO is  not 'present' 

    transform implementation:

        if $Idx present and $Scale != 0:
             $DST:64 =: $Idx:64
        if $Idx present and $Scale \in  {2, 4, 8}:
             CS transform for SHL64ri $DST:64, Log2($Scale)
        
	if not $Idx present:
             MOV64rr $DST:64, $0x0

        if $Base present:
             CS transform for ADD64rr $DST:64, $BASE:64

        if $Offset present and $Offset != 0:
             CS transform for ADD64ri $DST:64, $Offset
   */

  /*
    LEA64r: $rsi = LEA64r $rdx, 2, $rcx, 73, $noreg

    Dst64: RDX
  */
  
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    MCRegister Dst64;
    MCRegister Dst32;
    if (X86::LEA64r == MI->getOpcode()) {
	Dst64 = MI->getOperand(0).getReg().asMCReg();
	Dst32 = TRI->getSubReg(Dst64, X86::sub_32bit);
    } else if (X86::LEA64_32r == MI->getOpcode()) {
	Dst32 = MI->getOperand(0).getReg().asMCReg();
	Dst64 = TRI->getMatchingSuperReg(Dst32, X86::sub_32bit, &X86::GR64RegClass);
    }
    
    MCRegister Dst16 = TRI->getSubReg(Dst64, X86::sub_16bit);
    MCRegister Dst8 = TRI->getSubReg(Dst64, X86::sub_8bit);

    Register Base = MI->getOperand(1).getReg();
    int64_t Scale = MI->getOperand(2).getImm();
    Register Index = MI->getOperand(3).getReg();
    int64_t Offset = MI->getOperand(4).getImm();
    MachineOperand& SegmentMO = MI->getOperand(5);

    auto r10 = X86::R10;
    auto r11 = X86::R11;
    auto r11w = X86::R11W;
    auto r11b = X86::R11B;
    auto r12 = X86::R12;

    auto FlagsSavedReg = X86::R13B;

    // Save flags since LEA shouldn't modify flags
    // [[LAHF]] := (AH := EFLAGS(SF:ZF:0:AF:0:PF:1:CF))
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
	.addReg(X86::RAX);
    BuildMI(*MBB, *MI, DL, TII->get(X86::LAHF));
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R13)
	.addReg(X86::RAX);
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX)
	.addReg(X86::R10);

    int IndexPresent = Index.isPhysical();

    if (IndexPresent && Scale != 0) {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), Dst64)
	    .addReg(Index);
    }

    int ScaleIsTwoFourOrEight = Scale == 2 || Scale == 4 || Scale == 8;
    int64_t ShiftBy = static_cast<int64_t>(std::log2(static_cast<double>(Scale)));

    /* then insert safe SHL64ri */
    if (IndexPresent && ScaleIsTwoFourOrEight) {
	assert(ShiftBy >= 1 && ShiftBy <= 63);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), r10)
	    .addImm(1ULL << 63ULL); // 2 ** 63

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), r11)
	    .addReg(r10);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), r11b)
	    .addReg(Dst8);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8ri), Dst8)
	    .addImm(1);

	BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), r11)
	    .addReg(r11)
	    .addImm(ShiftBy);

	BuildMI(*MBB, *MI, DL, TII->get(X86::SHL64ri), Dst64)
	    .addReg(Dst64)
	    .addImm(ShiftBy);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), r10)
	    .addReg(r10)
	    .addImm(ShiftBy);

	BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), r11)
	    .addReg(r11)
	    .addReg(r10);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), Dst64)
	    .addReg(Dst64)
	    .addReg(r11);

	BuildMI(*MBB, *MI, DL, TII->get(X86::SUB64rr), Dst64)
	    .addReg(Dst64)
	    .addReg(r10);
    }

    if (!IndexPresent) {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Dst64)
	    .addImm(0);
    }

    int BasePresent = Base.isPhysical(); // should probably always be true

    /* then CS safely add Dst64 and Base regs together using ADD64rr transform */
    if (BasePresent) {
	MCRegister Src64 = Base.asMCReg();
	MCRegister Src16 = TRI->getSubReg(Src64, X86::sub_16bit);
	
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	    .addImm(1ULL << 48ULL); // 2**48

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
	    .addReg(Dst16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	    .addImm(1);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	    .addImm(1ULL << 48ULL); // 2 ** 48

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	    .addReg(Src16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16)
	    .addImm(1);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R10)
	    .addReg(X86::R10)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
	    .addReg(X86::R11)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Dst64)
	    .addReg(Dst64)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
	    .addReg(Src64)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R10D)
	    .addReg(X86::R10D)
	    .addReg(X86::R11D);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Dst64)
	    .addReg(Dst64)
	    .addReg(Src64);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
	    .addReg(X86::R11)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
	    .addReg(Src64)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
	    .addReg(X86::R10)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Dst64)
	    .addReg(Dst64)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Dst16)
	    .addReg(X86::R10W);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Src16)
	    .addReg(X86::R11W);
    }

    /* then safe ADD64ri $DST64, Offset */
    if (Offset != 0) {
	MCRegister Src64 = X86::R12;
	MCRegister Src16 = TRI->getSubReg(Src64, X86::sub_16bit);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), Src64)
	    .addImm(Offset);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	    .addImm(1ULL << 48ULL); // 2**48

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R10W)
	    .addReg(Dst16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Dst16)
	    .addImm(1);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	    .addImm(1ULL << 48ULL); // 2 ** 48

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), X86::R11W)
	    .addReg(Src16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16ri), Src16)
	    .addImm(1);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R10)
	    .addReg(X86::R10)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), X86::R11)
	    .addReg(X86::R11)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Dst64)
	    .addReg(Dst64)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), Src64)
	    .addReg(Src64)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ADD32rr), X86::R10D)
	    .addReg(X86::R10D)
	    .addReg(X86::R11D);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ADC64rr), Dst64)
	    .addReg(Dst64)
	    .addReg(Src64);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R11)
	    .addReg(X86::R11)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROL64ri), Src64)
	    .addReg(Src64)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::ROR64ri), X86::R10)
	    .addReg(X86::R10)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::RCL64ri), Dst64)
	    .addReg(Dst64)
	    .addImm(16);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Dst16)
	    .addReg(X86::R10W);

	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV16rr), Src16)
	    .addReg(X86::R11W);
    }

    // clear top 32 bits of dst register
    if (X86::LEA64_32r == MI->getOpcode()) {
	BuildMI(*MBB, *MI, DL, TII->get(X86::MOV32rr), Dst32)
	    .addReg(Dst32);
    }

    // restore EFLAGS (saved in R13)
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::R10)
	.addReg(X86::RAX);
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX)
	.addReg(X86::R13);
    BuildMI(*MBB, *MI, DL, TII->get(X86::SAHF));
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64rr), X86::RAX)
	.addReg(X86::R10);    
}

void
X86_64CompSimpMitigationPass::insertSafeAdd8rmBefore(MachineInstr* MI)
{
    MachineBasicBlock *MBB = MI->getParent();
    MachineFunction *MF = MBB->getParent();
    DebugLoc DL = MI->getDebugLoc();
    const auto &STI = MF->getSubtarget();
    auto *TII = STI.getInstrInfo();
    auto *TRI = STI.getRegisterInfo();
    auto &MRI = MF->getRegInfo();

    MCRegister Dst8 = MI->getOperand(1).getReg().asMCReg();

    MachineOperand& Base = MI->getOperand(2);
    MachineOperand& Scale = MI->getOperand(3);
    MachineOperand& Idx = MI->getOperand(4);
    MachineOperand& Offset = MI->getOperand(5);
    MachineOperand& Segment = MI->getOperand(6);

    // Load the value from memory
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rm), X86::R12B)
	.add(Base)
	.add(Scale)
	.add(Idx)
	.add(Offset)
	.add(Segment);

    // do the ADD8rr transform
    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R10)
	.addImm(1ULL << 31ULL);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R10B)
	.addReg(Dst8);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV64ri), X86::R11)
	.addImm(1ULL << 31ULL);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), X86::R11B)
	.addReg(X86::R12B);

    BuildMI(*MBB, *MI, DL, TII->get(X86::ADD64rr), X86::R10)
	.addReg(X86::R10)
	.addReg(X86::R11);

    BuildMI(*MBB, *MI, DL, TII->get(X86::MOV8rr), Dst8)
	.addReg(X86::R10B);

    BuildMI(*MBB, *MI, DL, TII->get(X86::BT64ri8))
	.addReg(X86::R10)
	.addImm(8);

}

void X86_64CompSimpMitigationPass::doX86CompSimpHardening(MachineInstr *MI, MachineFunction& MF) {
  /* llvm::errs() << "mitigating: " << *MI << "\n"; */
  const auto &STI = MF.getSubtarget();
  auto *TII = STI.getInstrInfo();
  
  switch (MI->getOpcode()) {
  case X86::LEA64_32r: 
  case X86::LEA64r: {
    insertSafeLea64rBefore(MI);
    llvm::errs() << "TODO: ADD CS STATS COLLECTOR FOR LEA64r\n";
    llvm::errs() << "TODO: ADD CS STATS COLLECTOR FOR LEA64_32r\n";
    MI->eraseFromParent();
    break;
  }
  case X86::ADD64ri8: {
    insertSafeAdd64ri8Before(MI);
    updateStats(MI, 1);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD64ri32: {
    insertSafeAdd64ri32Before(MI);
    updateStats(MI, 2);
    MI->eraseFromParent();
    break;
  }
  // case X86::ADD64mi32: {
  //   insertSafeAdd64mi32Before(MI);
  //   updateStats(MI, 3);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::ADD64mi8: {
  //   insertSafeAdd64mi8Before(MI);
  //   updateStats(MI, 4);
  //   MI->eraseFromParent();
  //   break;
  // }
  // case X86::ADD64mr: {
  //   insertSafeAdd64mrBefore(MI);
  //   updateStats(MI, 5);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::ADD64rm: {
    insertSafeAdd64rmBefore(MI);
    updateStats(MI, 6);
    MI->eraseFromParent();
    break;
  }
  case X86::ADD64rr: {
    insertSafeAdd64Before(MI);
    updateStats(MI, 7);
    MI->eraseFromParent();
    break;
  }
  // case X86::ADC64rr: {
  //   insertSafeAdc64Before(MI);
  //   updateStats(MI, 8); MI->eraseFromParent();
  //   break;
  // }
  // case X86::ADC64rm: {
  //   insertSafeAdc64rmBefore(MI);
  //   updateStats(MI, 9);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::ADC64mr: {
    insertSafeAdc64mrBefore(MI);
    updateStats(MI, 10);
    MI->eraseFromParent();
    break;
  }
  //  case X86::ADC64ri8: {
  //    insertSafeAdc64ri8Before(MI);
  //    updateStats(MI, 11);
  //    MI->eraseFromParent();
  //    break;
  //  }
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
  case X86::ADD32ri: {
    insertSafeAdd32riBefore(MI);
    llvm::errs() << "TODO: insert CS stats collecting for ADD32ri\n";
    MI->eraseFromParent();
    break;
  }
  // case X86::ADC32mi8: {
  //   insertSafeAdc32mi8Before(MI);
  //   updateStats(MI, 16);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::ADD8rm: {
      insertSafeAdd8rmBefore(MI);
      llvm::errs() << "TODO: compsimp cs statistics for ADD8rm\n";
      MI->eraseFromParent();
      break;
  }
  case X86::AND64rm: {
      insertSafeAnd64rmBefore(MI);
      llvm::errs() << "TODO: compsimp cs statistics for AND64rm\n";
      MI->eraseFromParent();
      break;
  }
  case X86::AND64rr: {
    insertSafeAnd64Before(MI);
    updateStats(MI, 18);
    MI->eraseFromParent();
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
  ///// case X86::OR8rm: {
  /////   assert(false && "comp simp todo");
  /////   break;
  ///// }
  ///// case X86::MUL64m: {
  /////   assert(false && "comp simp todo");
  /////   break;
  ///// }
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
  case X86::XOR32rr: {
    insertSafeXor32Before(MI);
    updateStats(MI, 37);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR32rm: {
    insertSafeXor32rmBefore(MI);
    updateStats(MI, 38);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR32ri: {
      insertSafeXor32riBefore(MI);
      llvm::errs() << "TODO: implement cs stats for XOR32ri\n";
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
  case X86::AND8ri: {
      insertSafeAnd8riBefore(MI);
      llvm::errs() << "TODO: CS stats for AND8ri\n";
      MI->eraseFromParent();
      break;
  }
  case X86::AND8rr: {
    insertSafeAnd8Before(MI);
    updateStats(MI, 46);
    MI->eraseFromParent();
    break;
  }
  case X86::TEST8ri: {
    insertSafeTest8riBefore(MI);
    updateStats(MI, 47);
    MI->eraseFromParent();
    break;
  }
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
  case X86::SAR8ri: {
    insertSafeSar8riBefore(MI);
    llvm::errs() << "TODO: cs stats for SAR8r1\n";
    MI->eraseFromParent();
    break;
  }
  case X86::SHR32rCL: {
    insertSafeShr32rClBefore(MI);
    updateStats(MI, 53); MI->eraseFromParent();
    break;
  }
  case X86::SHR32ri: {
    insertSafeShr32riBefore(MI);
    updateStats(MI, 54);
    MI->eraseFromParent();
    break;
  }
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
  case X86::SHL32ri: {
    insertSafeShl32riBefore(MI);
    updateStats(MI, 57);
    MI->eraseFromParent();
    break;
  }
  // case X86::SAR32r1: {
  //   insertSafeSar32r1Before(MI);
  //   updateStats(MI, 58);
  //   MI->eraseFromParent();
  //   break;
  // }
  case X86::SAR64ri: {
    insertSafeSar64riBefore(MI);
    updateStats(MI, 59);
    MI->eraseFromParent();
    break;
  }
  case X86::SHR64r1: {
      insertSafeShr64r1Before(MI);
      llvm::errs() << "TODO: CS stats counting to SHR64r1\n";
      MI->eraseFromParent();
      break;
  }
  case X86::SHR64ri: {
    insertSafeShr64riBefore(MI);
    updateStats(MI, 60);
    MI->eraseFromParent();
    break;
  }
  case X86::SHL64ri: {
    insertSafeShl64riBefore(MI);
    updateStats(MI, 61); MI->eraseFromParent();
    break;
  }
  case X86::AND16rr: {
    insertSafeAnd16Before(MI);
    updateStats(MI, 62);
    MI->eraseFromParent();
    break;
  }
  case X86::OR8rr: {
      insertSafeOr8Before(MI);
      updateStats(MI, 63);
      MI->eraseFromParent();
      break;
  }
  case X86::OR8ri: {
      insertSafeOr8riBefore(MI);
      llvm::errs() << "TODO: implement cs stats tracking for OR8ri\n";
      MI->eraseFromParent();
      break;
  }
  case X86::OR16rr: {
    insertSafeOr16Before(MI);
    updateStats(MI, 64);
    MI->eraseFromParent();
    break;
  }
  case X86::XOR16rr: {
    insertSafeXor16Before(MI);
    updateStats(MI, 65);
    MI->eraseFromParent();
    break;
  }
  // case X86::SUB16rr: {
  //   // TODO: not present in libNa to debug
  //   insertSafeSub16Before(MI);
  //   updateStats(MI, 67);
  //   MI->eraseFromParent();
  //   break;
  // }
    ///// case X86::SUB32rm:
    ///// case X86::ADD8rr: {
    /////   // TODO: not present in libNa to debug
    /////   assert(false && "support sub8");
    /////   break;
    ///// }
  case X86::ADD8ri: {
    insertSafeAdd8riBefore(MI);
    llvm::errs() << "TODO: add CS stats tracking for ADD8ri\n";
    MI->eraseFromParent();
    break;
  }
  // case X86::ADD16rr: {
  //   insertSafeAdd16Before(MI);
  //   updateStats(MI, 70);
  //   MI->eraseFromParent();
  //   break;
  // }
  /// case X86::SHR64rCL: {
  ///   insertSafeShr64Before(MI);
  ///   updateStats(MI, 72); MI->eraseFromParent();
  ///   break;
  /// }
  ///// case X86::SHR8rCL: {
  ///// assert(false && "support shr8cl");
  ///// updateStats(MI, 75); MI->eraseFromParent();
  ///// }
  case X86::MUL32r: {
    insertSafeMul32rBefore(MI);
    updateStats(MI, 76);
    MI->eraseFromParent();
    break;
  }
  case X86::MUL64r: {
      insertSafeMul64rBefore(MI);
      llvm::errs() << "TODO: add cs stats to MUL64r\n";
      MI->eraseFromParent();
      break;
  }
  case X86::MUL64m: {
      insertSafeMul64rBefore(MI);
      llvm::errs() << "TODO: add cs stats to MUL64m\n";
      MI->eraseFromParent();
      break;
  }
  case X86::CMP64rr: {
    insertSafeCmp64rrBefore(MI);
    updateStats(MI, 77);
    MI->eraseFromParent();
    break;
  }
  case X86::CMP64rm: {
    insertSafeCmp64rmBefore(MI);
    updateStats(MI, 78);
    MI->eraseFromParent();
    break;
  }
  case X86::CMP64mr: {
    insertSafeCmp64mrBefore(MI);
    llvm::errs() << "TODO: CS stats for CMP64mr\n";
    MI->eraseFromParent();
    break;
  }
  case X86::CMP32rr: {
    insertSafeCmp32rrBefore(MI);
    updateStats(MI, 79);
    MI->eraseFromParent();
    break;
  }
  case X86::CMP32rm: {
    insertSafeCmp32rmBefore(MI);
    updateStats(MI, 80);
    MI->eraseFromParent();
    break;
  }
  /// case X86::CMP32mr: {
  ///   insertSafeCmp32mrBefore(MI);
  ///   updateStats(MI, 81);
  ///   MI->eraseFromParent();
  ///   break;
  /// }
  case X86::SUB8rr: {
    insertSafeSub8rrBefore(MI);
    updateStats(MI, 66);
    MI->eraseFromParent();
    break;
  }
  /// case X86::CMP8rr: {
  ///   insertSafeCmp8rrBefore(MI);
  ///   updateStats(MI, 82);
  ///   MI->eraseFromParent();
  ///   break;
  /// }
  ///  case X86::SBB32rr: {
  ///    insertSafeSbb32Before(MI);
  ///    updateStats(MI, 83);
  ///    MI->eraseFromParent();
  ///    break;
  ///  }
  case X86::IMUL32rr: {
    insertSafeIMul32rrBefore(MI);
    updateStats(MI, 84);
    MI->eraseFromParent();
    break;
  }
  case X86::IMUL32rm: {
    insertSafeIMul32rmBefore(MI);
    updateStats(MI, 85);
    MI->eraseFromParent();
    break;
  }
  case X86::IMUL64rr: {
    insertSafeIMul64rrBefore(MI);
    updateStats(MI, 86);
    MI->eraseFromParent();
    break;
  }
  case X86::IMUL64rri8: {
    insertSafeIMul64rri8Before(MI);
    updateStats(MI, 87);
    MI->eraseFromParent();
    break;
  }
  case X86::IMUL64rri32: {
    insertSafeIMul64rri32Before(MI);
    updateStats(MI, 88);
    MI->eraseFromParent();
    break;
  }
  default: {
    errs() << "Unsupported opcode: " << TII->getName(MI->getOpcode()) << '\n';
    break;
  }
    //  case X86::VPXORrr: {
    //    insertSafeVPXorrrBefore(MI);
    //    updateStats(MI, 86);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPXORrm: {
    //    insertSafeVPXorrmBefore(MI);
    //    updateStats(MI, 87);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPXORYrr: {
    //    insertSafeVPXoryrrBefore(MI);
    //    updateStats(MI, 88);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPXORYrm: {
    //    insertSafeVPXoryrmBefore(MI);
    //    updateStats(MI, 89);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::PXORrr: {
    //    insertSafeVPXorrrBefore(MI);
    //    updateStats(MI, 90);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::PXORrm: {
    //    insertSafeVPXorrmBefore(MI);
    //    updateStats(MI, 91);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPORrr: {
    //    insertSafeVPOrrrBefore(MI);
    //    updateStats(MI, 92);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPORYrr: {
    //    insertSafeVPOryrrBefore(MI);
    //    updateStats(MI, 93);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::PORrr: {
    //    insertSafeVPOrrrBefore(MI);
    //    updateStats(MI, 94);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::PORrm: {
    //    insertSafeVPOrrmBefore(MI);
    //    updateStats(MI, 95);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPADDDrr: {
    //    insertSafeVPAddDrrBefore(MI);
    //    updateStats(MI, 96);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPADDDrm: {
    //    insertSafeVPAddDrmBefore(MI);
    //    updateStats(MI, 97);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPADDDYrr: {
    //    insertSafeVPAddDYrrBefore(MI);
    //    updateStats(MI, 98);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPADDDYrm: {
    //    insertSafeVPAddDYrmBefore(MI);
    //    updateStats(MI, 99);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPADDQrr: {
    //    insertSafeVPAddQrrBefore(MI);
    //    updateStats(MI, 100);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPADDQrm: {
    //    insertSafeVPAddQrmBefore(MI);
    //    updateStats(MI, 101);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPADDQYrr: {
    //    insertSafeVPAddQYrrBefore(MI);
    //    updateStats(MI, 102);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPADDQYrm: {
    //    insertSafeVPAddQYrmBefore(MI);
    //    updateStats(MI, 103);
    //    MI->eraseFromParent();
    //    break;
    //  }
  case X86::PADDDrr: {
      insertSafePADDDrrBefore(MI);
      llvm::errs() << "TODO: add cs stats for PADDDrr\n";
      MI->eraseFromParent();
      break;
  }
  case X86::PADDDrm: {
      // yes, same func call
      insertSafePADDDrrBefore(MI);
      llvm::errs() << "TODO: add cs stats for PADDDrm\n";
      MI->eraseFromParent();
      break;
  }
  case X86::PADDQrr: {
      insertSafePADDQBefore(MI);
      updateStats(MI, 104);
      MI->eraseFromParent();
      break;
  }
  case X86::PADDQrm: {
      insertSafePADDQBefore(MI);
      updateStats(MI, 105);
      MI->eraseFromParent();
      break;
  }
    //  case X86::VPANDrr: {
    //    insertSafeVPAndrrBefore(MI);
    //    updateStats(MI, 106);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPANDrm: {
    //    insertSafeVPAndrmBefore(MI);
    //    updateStats(MI, 107);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::PANDrr: {
    //    insertSafeVPAndrrBefore(MI);
    //    updateStats(MI, 108);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::PANDrm: {
    //    insertSafeVPAndrmBefore(MI);
    //    updateStats(MI, 109);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPSHUFBrr: {
    //    insertSafeVPShufBrrBefore(MI);
    //    updateStats(MI, 110);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPSHUFBYrr: {
    //    insertSafeVPShufBYrrBefore(MI);
    //    updateStats(MI, 111);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPSHUFBYrm: {
    //    insertSafeVPShufBYrmBefore(MI);
    //    updateStats(MI, 112);
    //    MI->eraseFromParent();
    //    break;
    //  }
    //  case X86::VPMULUDQrr: {
    //    assert(false && "VPMULUDQrr not implemented");
    //    break;
    //  }
}
}

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

	// record cycle counts
	if (RecordTestCycleCounts)
	{
	    BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
		.addReg(X86::RAX);
	    BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
		.addReg(X86::RDX);
	    
	    BuildMI(*MBB, &MI, DL, TII->get(X86::CPUID));
	    BuildMI(*MBB, &MI, DL, TII->get(X86::RDTSC));

	    BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r), X86::RDX);

	    BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0x110ull)
	      .addReg(0)
	      .addReg(X86::RAX);

	    BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r), X86::RAX);
	}

	if (Op == "LEA64r") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::LEA64r), X86::RSI)
		.addReg(X86::RDX) // base
		.addImm(2) // scale
		.addReg(X86::RCX) //index
		.addImm(73) //displacement
		.addReg(0); //no segment reg
	}
	else if (Op == "LEA64_32r") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::LEA64_32r), X86::ESI)
		.addReg(X86::RDX) // base
		.addImm(2) // scale
		.addReg(X86::RCX) //index
		.addImm(73) //displacement
		.addReg(0); //no segment reg
	}
	else if (Op == "AND64rm") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::AND64rm), X86::RSI)
		.addReg(X86::RSI)
		.addReg(X86::RDX)
		.addImm(0)
		.addReg(0)
		.addImm(0)
		.addReg(0);
	}
        else if (Op == "ADD64ri8") {
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64ri8), X86::RSI)
              .addReg(X86::RSI)
              .addImm(0x25);
	}
        else if (Op == "ADD64mi32")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64mi32))
	    .addReg(X86::RSI)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addImm(0x25);
	else if (Op == "ADD32ri") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::ADD32ri), X86::ESI)
		.addReg(X86::ESI)
		.addImm(0xFFFF'FFFFUL);
	}
        else if (Op == "ADD32ri8") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::ADD32ri8), X86::ESI)
		.addReg(X86::ESI)
		.addImm(1ULL << 7ULL);
	}
        else if (Op == "ADD64ri32")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64ri32), X86::RSI)
              .addReg(X86::RSI)
              .addImm(0x25);
        else if (Op == "ADD64mi8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64mi8))
              .addReg(X86::RSI)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addImm(0x25);
        else if (Op == "ADD64mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64mr))
              .addReg(X86::RSI)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::RDX);
        else if (Op == "ADD64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64rm), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "ADD64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD64rr), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX);
        else if (Op == "ADC64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC64rr), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX);
        else if (Op == "ADC64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC64rm), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "ADC64mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC64mr))
              .addReg(X86::RSI)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::RDX);
        else if (Op == "ADC32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC32ri8), X86::ESI)
              .addReg(X86::ESI)
              .addImm(0x25);
        else if (Op == "ADD32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD32rr), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::EDX);
        else if (Op == "ADD32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD32rm), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "ADC32mi8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADC32mi8))
              .addReg(X86::RSI)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addImm(0x25);
        else if (Op == "ADD8rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD8rm), X86::SIL)
              .addReg(X86::SIL)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "AND64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND64rr), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX);
        else if (Op == "AND64ri32")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND64ri32), X86::RSI)
              .addReg(X86::RSI)
              .addImm(0x25);
        else if (Op == "AND64ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND64ri8), X86::RSI)
              .addReg(X86::RSI)
              .addImm(0x25);
        else if (Op == "AND32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND32rr), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::EDX);
        else if (Op == "AND32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND32ri8), X86::ESI)
              .addReg(X86::ESI)
              .addImm(0x25);
        else if (Op == "AND32ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND32ri), X86::ESI)
              .addReg(X86::ESI)
              .addImm(0x25);
        else if (Op == "OR64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR64rr), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX);
        else if (Op == "OR64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR64rm), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "OR64ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR64ri8), X86::RSI)
              .addReg(X86::RSI)
              .addImm(0x25);
        else if (Op == "OR32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR32rr), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::EDX);
        else if (Op == "OR32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR32ri8), X86::ESI)
              .addReg(X86::ESI)
              .addImm(0x25);
        else if (Op == "OR8rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR8rm), X86::SIL)
              .addReg(X86::SIL)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "IMUL32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::IMUL32rm), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "XOR64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR64rr), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX);
        else if (Op == "XOR64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR64rm), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "XOR64mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR64mr))
              .addReg(X86::RSI)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::RDX);
        else if (Op == "XOR32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR32rr), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::EDX);
        else if (Op == "XOR32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR32rm), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
	else if (Op == "XOR32ri")
	    BuildMI(*MBB, &MI, DL, TII->get(X86::XOR32ri), X86::ESI)
              .addReg(X86::ESI)
              .addImm(0x25);
        else if (Op == "XOR32ri8")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR32ri8), X86::ESI)
              .addReg(X86::ESI)
              .addImm(0x25);
        else if (Op == "XOR8rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR8rm), X86::SIL)
              .addReg(X86::SIL)
              .addReg(X86::RDX)
              .addImm(0)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "SUB64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB64rr), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX);
        else if (Op == "SUB64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB64rm), X86::RSI)
              .addReg(X86::RSI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "SUB32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB32rr), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::EDX);
        else if (Op == "TEST32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::TEST32rr))
              .addReg(X86::ESI)
              .addReg(X86::EDX);
	else if (Op == "AND8ri")
	    BuildMI(*MBB, &MI, DL, TII->get(X86::AND8ri), X86::SIL)
		.addReg(X86::SIL)
		.addImm(0x33);
        // else if (Op == "AND8rr")
        //         BuildMI(*MBB, &MI, DL, TII->get(X86::AND8rr),
        //         X86::SIL).addReg(X86::SIL).addReg(X86::DL);
        else if (Op == "TEST8ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::TEST8ri))
              .addReg(X86::SIL)
              .addImm(0x25);
        else if (Op == "TEST8mi")
          BuildMI(*MBB, &MI, DL, TII->get(X86::TEST8mi))
              .addReg(X86::RSI)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addImm(0x25);
        else if (Op == "AND16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::AND16rr), X86::SI)
              .addReg(X86::SI)
              .addReg(X86::DX);
        else if (Op == "OR16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR16rr), X86::SI)
              .addReg(X86::SI)
              .addReg(X86::DX);
        else if (Op == "XOR16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::XOR16rr), X86::SI)
              .addReg(X86::SI)
              .addReg(X86::DX);
        else if (Op == "SUB16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB16rr), X86::SI)
              .addReg(X86::SI)
              .addReg(X86::DX);
	else if (Op == "ADD8ri") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::ADD8ri), X86::SIL)
		.addReg(X86::SIL)
		.addImm(0xFF);
	}
        else if (Op == "ADD16rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD16rr), X86::SI)
              .addReg(X86::SI)
              .addReg(X86::DX);
        else if (Op == "OR8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::OR8rr), X86::SIL)
              .addReg(X86::SIL)
              .addReg(X86::DL);
	else if (Op == "OR8ri")
	    BuildMI(*MBB, &MI, DL, TII->get(X86::OR8ri), X86::SIL)
		.addReg(X86::SIL)
		.addImm(0XCCULL);
        else if (Op == "SUB8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB8rr), X86::SIL)
              .addReg(X86::SIL)
              .addReg(X86::DL);
        else if (Op == "ADD8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::ADD8rr), X86::SIL)
              .addReg(X86::SIL)
              .addReg(X86::DL);
        else if (Op == "SUB32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SUB32rm), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::RDX)
              .addImm(1)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "SHR64rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR64rCL), X86::RSI)
              .addReg(X86::RSI);
        else if (Op == "SHR32rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR32rCL), X86::ESI)
              .addReg(X86::ESI);
        else if (Op == "SHL32rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL32rCL), X86::EDX)
              .addReg(X86::EDX);
        /* else if (Op == "SHR16rSIL") */
        /*   BuildMI(*MBB, &MI, DL, TII->get(X86::SHR16rSIL), X86::SI) */
        /*       .addReg(X86::SI); */
        else if (Op == "SHL16rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL16rCL), X86::SI)
              .addReg(X86::SI);
        else if (Op == "SHR8rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR8rCL), X86::SIL)
              .addReg(X86::SIL);
        else if (Op == "SHL8rCL")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL8rCL), X86::SIL)
              .addReg(X86::SIL);
        else if (Op == "SHR8ri") {
                BuildMI(*MBB, &MI, DL, TII->get(X86::SHR8ri), X86::SIL)
		    .addReg(X86::SIL)
		    .addImm(2);
	} else if (Op == "SHR32ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR32ri), X86::ESI)
              .addReg(X86::ESI)
              .addImm(17);
        else if (Op == "SHL32ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL32ri), X86::ESI)
              .addReg(X86::ESI)
              .addImm(0x8);
        else if (Op == "SHL64ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHL64ri), X86::RSI)
              .addReg(X86::RSI)
              .addImm(0x25);
        else if (Op == "SAR64ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SAR64ri), X86::RSI)
              .addReg(X86::RSI)
              .addImm(0x25);
	else if (Op == "SHR64r1")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR64r1), X86::RSI)
              .addReg(X86::RSI);
        else if (Op == "SHR64ri")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR64ri), X86::RSI)
              .addReg(X86::RSI)
              .addImm(0x25);
        else if (Op == "SAR8ri")
                BuildMI(*MBB, &MI, DL, TII->get(X86::SAR8ri), X86::SIL)
		    .addReg(X86::SIL)
		    .addImm(3);
        else if (Op == "SHR32r1")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SHR32r1), X86::ESI)
              .addReg(X86::ESI);
        else if (Op == "SAR32r1")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SAR32r1), X86::ESI)
              .addReg(X86::ESI);
        else if (Op == "MUL32r")
          BuildMI(*MBB, &MI, DL, TII->get(X86::MUL32r))
              .addReg(X86::ESI);
	else if (Op == "MUL64r") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::MUL64r))
		.addReg(X86::RSI);
	} else if (Op == "MUL64m") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::MUL64m))
		.addReg(X86::RCX)
		.addImm(1)
		.addReg(0)
		.addImm(0)
		.addReg(0);
	} else if (Op == "CMP64rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP64rr))
              .addReg(X86::RSI)
              .addReg(X86::RDX);
        else if (Op == "CMP64rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP64rm))
              .addReg(X86::RSI)
              .addReg(X86::RDX)
              .addImm(0)
              .addReg(0)
              .addImm(0)
              .addReg(0);
	else if (Op == "CMP64mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP64mr))
              .addReg(X86::RSI)
	      .addImm(0)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::RDX);
        else if (Op == "CMP32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP32rr))
              .addReg(X86::ESI)
              .addReg(X86::EDX);
        else if (Op == "CMP32rm")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP32rm))
              .addReg(X86::ESI)
              .addReg(X86::RDX)
              .addImm(0)
              .addReg(0)
              .addImm(0)
              .addReg(0);
        else if (Op == "CMP32mr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP32mr))
              .addReg(X86::RDX)
              .addImm(0)
              .addReg(0)
              .addImm(0)
              .addReg(0)
              .addReg(X86::ESI);
        else if (Op == "CMP8rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::CMP8rr))
              .addReg(X86::SIL)
              .addReg(X86::DL);
        else if (Op == "SBB32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::SBB32rr), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::EDX);
        else if (Op == "IMUL32rr")
          BuildMI(*MBB, &MI, DL, TII->get(X86::IMUL32rr), X86::ESI)
              .addReg(X86::ESI)
              .addReg(X86::EDX);
	else if (Op == "PADDDrr") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::PADDDrr), X86::XMM0)
		.addReg(X86::XMM0)
		.addReg(X86::XMM1);
        }
	else if (Op == "PADDDrm") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::PADDDrm), X86::XMM0)
		.addReg(X86::XMM0)
		.addReg(X86::RDX)
		.addImm(1)
		.addReg(0)
		.addImm(0)
		.addReg(0);
        }
	else if (Op == "PADDQrr") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::PADDQrr), X86::XMM0)
		.addReg(X86::XMM0)
		.addReg(X86::XMM1);
        }
	else if (Op == "PADDQrm") {
	    BuildMI(*MBB, &MI, DL, TII->get(X86::PADDQrm), X86::XMM0)
		.addReg(X86::XMM0)
		.addReg(X86::RDX)
		.addImm(1)
		.addReg(0)
		.addImm(0)
		.addReg(0);
        }

	if (RecordTestCycleCounts)
	{
	    BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
		.addReg(X86::RAX);
	    BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r))
		.addReg(X86::RDX);
	    
	    BuildMI(*MBB, &MI, DL, TII->get(X86::RDTSCP));
	    BuildMI(*MBB, &MI, DL, TII->get(X86::CPUID));

	    BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64rm))
		.addReg(X86::R10)
		.addReg(X86::RDI)
		.addImm(1)
		.addReg(0)
		.addImm(0x110ull)
		.addReg(0);

	    BuildMI(*MBB, &MI, DL, TII->get(X86::SUB64rr), X86::R10D)
		.addReg(X86::R10D)
		.addReg(X86::EAX);

	    BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64mr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0x110ull)
	      .addReg(0)
	      .addReg(X86::R10);

	    BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r), X86::RDX);
	    BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r), X86::RAX);
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

	  BuildMI(*MBB, &MI, DL, TII->get(X86::PUSH64r), X86::R15);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64rr), X86::R15)
	      .addReg(X86::RAX);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::LAHF));
	  BuildMI(*MBB, &MI, DL, TII->get(X86::ROR64ri), X86::RAX)
	      .addReg(X86::RAX)
	      .addImm(8ull);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV8mr))
	      .addReg(X86::RDI)
	      .addImm(0)
	      .addReg(0)
	      .addImm(0x80ULL)
	      .addReg(0)
	      .addReg(X86::AL);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOV64rr), X86::RAX)
	    .addReg(X86::R15);
	  BuildMI(*MBB, &MI, DL, TII->get(X86::POP64r), X86::R15);

	  // store vector regs into outstate struct
	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOVDQAmr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0x90ull)
	      .addReg(0)
	      .addReg(X86::XMM0);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOVDQAmr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0xA0ull)
	      .addReg(0)
	      .addReg(X86::XMM1);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOVDQAmr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0xB0ull)
	      .addReg(0)
	      .addReg(X86::XMM2);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOVDQAmr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0xC0ull)
	      .addReg(0)
	      .addReg(X86::XMM3);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOVDQAmr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0xD0ull)
	      .addReg(0)
	      .addReg(X86::XMM4);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOVDQAmr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0xE0ull)
	      .addReg(0)
	      .addReg(X86::XMM5);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOVDQAmr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0xF0ull)
	      .addReg(0)
	      .addReg(X86::XMM6);

	  BuildMI(*MBB, &MI, DL, TII->get(X86::MOVDQAmr))
	      .addReg(X86::RDI)
	      .addImm(1)
	      .addReg(0)
	      .addImm(0x100ull)
	      .addReg(0)
	      .addReg(X86::XMM7);
	}
      }
    }
  }
}

bool X86_64CompSimpMitigationPass::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableCompSimp)
    return false;

  /* llvm::errs() << "Running on MachineFunction: " << MF.getName() << "\n"; */
  if (MF.getName().startswith("x86compsimptest")) {
    setupTest(MF);
    if (MF.getName().contains("_transformed")) {
      std::vector<MachineInstr *> MIs;
      for (auto &MBB : MF) {
        for (auto &MI : MBB) {
            MIs.push_back(&MI);
        }
      }
      for (auto &MI : MIs) {
	doX86CompSimpHardening(MI, MF);
      }
    }
    return true;
  }

  /* static class member: don't reparse the CSV file on each MachineFunction
     in the compilation unit */
  if (!CSVFileAlreadyParsed) {
    this->readCheckerAlertCSV(CompSimpCSVPath);
    CSVFileAlreadyParsed = true;
  }

  if (!shouldRunOnMachineFunction(MF)) {
    return false; // Doesn't modify the func if not running
  }

  bool doesModifyFunction{false};
  std::string SubName = MF.getName().str();
  bool SameSymbolNameAlreadyInstrumented =
      FunctionsInstrumented.end() != FunctionsInstrumented.find(SubName);
  if (SameSymbolNameAlreadyInstrumented) {
    /* errs() << "Trying to transform two different functions with identical " */
    /*           "symbol names: " */
    /*        << SubName << '\n'; */
    assert(!SameSymbolNameAlreadyInstrumented &&
           "Trying to transform two different functions"
           " with identical symbol names is not allowed");
  }
  FunctionsInstrumented.insert(SubName);

  std::vector<MachineInstr *> Instructions;
  for (auto &MBB : MF) {
    for (llvm::MachineBasicBlock::iterator I = MBB.begin(), E = MBB.end();
         I != E; ++I) {
      llvm::MachineInstr &MI = *I;
      DebugLoc DL = MI.getDebugLoc();
      const auto &STI = MF.getSubtarget();
      auto *TII = STI.getInstrInfo();

      if (MI.getOpcode() == X86::SBB64ri32) {
        int CurIdx = MI.getOperand(2).getImm();

        if (this->shouldRunOnInstructionIdx(SubName, CurIdx)) {
          I++;
          MachineInstr &NextMI = *I;
          std::string CurOpcodeName = TII->getName(NextMI.getOpcode()).str();
          /* errs() << "hardening insn at idx " << CurIdx */
          /*        << " the MIR insn is: " << CurOpcodeName */
          /*        << " the full MI is: " << NextMI << '\n'; */

          // don't count 'meta' insns like debug info, CFI indicators
          // as instructions in the instruction idx counts
          // we are only on LLVM14, so this is the only descriptor available.
          const MCInstrDesc &MIDesc = NextMI.getDesc();

          if (NextMI.getFlag(MachineInstr::MIFlag::FrameSetup)) {
            continue;
          }

          auto CurNameAndInsnIdx = std::pair<std::string, int>(SubName, CurIdx);
          auto Iter = ExpectedOpcodeNames.find(CurNameAndInsnIdx);
          assert(Iter != ExpectedOpcodeNames.end());
          const std::string &ExpectedOpcode = Iter->second;

          // If there was a mismatch, then find the originating checker
          // alert CSV row and print it out compared to this insn.
          bool SameOpcode = false;
          if (CurOpcodeName == "ADD8ri" && ExpectedOpcode == "ADD8i8") {
            SameOpcode = true;
          }
          if (CurOpcodeName == "XOR8ri" && ExpectedOpcode == "XOR8i8") {
            SameOpcode = true;
          }
          if (CurOpcodeName == "AND32ri" && ExpectedOpcode == "AND32i32") {
            SameOpcode = true;
          }
          // support add32ri
          if (CurOpcodeName == "ADD32ri" && ExpectedOpcode == "ADD32i32") {
            SameOpcode = true;
          }
          if (CurOpcodeName == "AND64ri32" && ExpectedOpcode == "AND64i32") {
            SameOpcode = true;
          }
          if (CurOpcodeName == "ADD64ri32" && ExpectedOpcode == "ADD64i32") {
            SameOpcode = true;
          }
          if (CurOpcodeName == "AND8ri" && ExpectedOpcode == "AND8i8") {
            SameOpcode = true;
          }
          // support or8ri
          if (CurOpcodeName == "OR8ri" && ExpectedOpcode == "OR8i8") {
            SameOpcode = true;
          }
          // support test8ri
          if (CurOpcodeName == "TEST8ri" && ExpectedOpcode == "TEST8i8") {
            SameOpcode = true;
          }
          
          if (!SameOpcode && CurOpcodeName.find(ExpectedOpcode) == std::string::npos) {
            auto IsCurCsvRow = [&](const CheckerAlertCSVLine &Row) {
              return Row.SubName == SubName && CurIdx == Row.InsnIdx;
            };

            auto ErrIter =
                std::find_if(this->RelevantCSVLines.begin(),
                             this->RelevantCSVLines.end(), IsCurCsvRow);
            assert(ErrIter != this->RelevantCSVLines.end());

            /* errs() << "Mismatch in instruction indices in function " << SubName */
            /*        << '\n'; */

            /* errs() << "CSV Row was:\n"; */
            /* ErrIter->Print(); */
            /* assert(false && "Mismatch in instruction indices"); */
            // exit(-1);
          }
          /* llvm::errs() << "Transforming instruction at idx " << CurIdx << "\n"; */
          Instructions.push_back(&NextMI);
          doesModifyFunction = true;
        }
      }
    }
  }

  for (MachineInstr *MI : Instructions) {
    doX86CompSimpHardening(MI, MF);
  }
  return doesModifyFunction;
}

// This will eventually check for the secret attribute. For now, just use
// function names.
bool X86_64CompSimpMitigationPass::shouldRunOnMachineFunction(
    MachineFunction &MF) {
  const std::string FuncName = MF.getName().str();
  auto FuncsIter = FunctionsToInstrument.find(FuncName);
  bool FoundFunction = FuncsIter != FunctionsToInstrument.end();
  return FoundFunction;
}

char X86_64CompSimpMitigationPass::ID = 0;

FunctionPass *llvm::createX86_64CompSimpMitigationPass() {
  return new X86_64CompSimpMitigationPass();
}

INITIALIZE_PASS(X86_64CompSimpMitigationPass, "csimp-mitigation",
                "Mitigations for computation simplication optimizations", true,
                true)

