#ifndef LLVM_ANALYSIS_HANDLESSECRETS_H
#define LLVM_ANALYSIS_HANDLESSECRETS_H

#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/InitializePasses.h"

// For Silent stores mitigation
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
// #include "MCTargetDesc/X86BaseInfo.h"

namespace llvm {

class HandlesSecrets : public AnalysisInfoMixin<HandlesSecrets> {
    friend AnalysisInfoMixin<HandlesSecrets>;
    static AnalysisKey Key;
public:
    using Result = StringRef;
    Result run(Function &F, FunctionAnalysisManager &AM);
}; // end class HandlesSecrets

class HandlesSecretsWrapperPass : public FunctionPass {
    bool FunctionHandlesSecrets{false};

public:
    static char ID;

    HandlesSecretsWrapperPass();
    ~HandlesSecretsWrapperPass() = default;

    bool getAnalysisResults() const {
        return FunctionHandlesSecrets;
    }
    bool runOnFunction(Function &F) override;
    void getAnalysisUsage(AnalysisUsage &AU) const override;

    bool functionHandlesSecrets() const { return FunctionHandlesSecrets; }
};

void initializeHandlesSecretsWrapperPassPass(PassRegistry &);

class HandlesSecretsPass : public AnalysisInfoMixin<HandlesSecretsPass> {
    raw_ostream &OS;
public:
    explicit HandlesSecretsPass(raw_ostream &OS) : OS(OS) {}
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

} // end namespace llvm

#endif // LLVM_ANALYSIS_HANDLESSECRETS_H