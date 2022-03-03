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

namespace llvm {

class HandlesSecrets : public AnalysisInfoMixin<HandlesSecrets> {
    friend AnalysisInfoMixin<HandlesSecrets>;
    static AnalysisKey Key;
public:
    using Result = StringRef;
    Result run(Function &F, FunctionAnalysisManager &AM);
}; // end class HandlesSecrets

class HandlesSecretsWrapperPass : public FunctionPass {
    bool FunctionHandlesSecrets = false;

public:
    static char ID;

    HandlesSecretsWrapperPass();
    ~HandlesSecretsWrapperPass() = default;

    bool getAnalysisResults() const {
        return FunctionHandlesSecrets;
    }
    bool runOnFunction(Function &F) override;
    void getAnalysisUsage(AnalysisUsage &AU) const override;
};

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

void initializeHandlesSecretsWrapperPassPass(PassRegistry &);

void initializeHandlesSecretsModulePassPass(PassRegistry &);

class HandlesSecretsModulePass : public ModulePass {
    std::set<StringRef> SecretHandlingFunctions;

public:
    static char ID;

    HandlesSecretsModulePass() : ModulePass(ID) {
        initializeHandlesSecretsModulePassPass(*PassRegistry::getPassRegistry());
    }
    ~HandlesSecretsModulePass() = default;

    // const std::set<StringRef> &getResults() const {
    //     return &SecretHandlingFunctions;
    // }

    bool functionHandlesSecrets(const Function &F) const {
        auto LookUpResult = SecretHandlingFunctions.find(F.getName());
        return LookUpResult != SecretHandlingFunctions.end();
    } 

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.setPreservesAll();
    }

    bool runOnModule(Module &M) override {
        errs() << "HandlesSecretsModulePass running on module " << M.getName() << '\n';
        // HandlesSecretsWrapperPass *HS = &getAnalysis<HandlesSecretsWrapperPass>();
        // for (Function &F : M.functions()) {
        //     if (HS->runOnFunction(F)) {
        //         SecretHandlingFunctions.insert(F.getName());
        //     }
        // }
        // errs() << "Functions handling secrets in module " << M.getName() << ": ";
        // for (auto S : SecretHandlingFunctions) {
        //     errs() << S << ", ";
        // }
        // errs() << '\n';

        return false; // Doesn't modify the module
    }
};

class HandlesSecretsPass : public AnalysisInfoMixin<HandlesSecretsPass> {
    raw_ostream &OS;
public:
    explicit HandlesSecretsPass(raw_ostream &OS) : OS(OS) {}
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

} // end namespace llvm

#endif // LLVM_ANALYSIS_HANDLESSECRETS_H