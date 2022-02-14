#include "llvm/Analysis/HandlesSecrets.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/InitializePasses.h"

namespace llvm {

AnalysisKey HandlesSecrets::Key;

StringRef HandlesSecrets::run(Function &F, FunctionAnalysisManager &AM) {
    for (auto &BB : F) {
        for (auto &Insn: BB) {
            // Calls can be one of call, callbr, invoke in the IR
            if (auto *CallInsn = dyn_cast<CallBase>(&Insn)) {
                if (auto *CalledFunction = CallInsn->getCalledFunction()) {
                    if (CalledFunction->isIntrinsic()) {
                        return "true";
                    }
                }
            }
        }
    }
    return "false";
}

PreservedAnalyses HandlesSecretsPass::run(Function &F, FunctionAnalysisManager &FAM) {
    OS << "Does function, " << F.getName() << ", handle secrets?: ";
    OS << FAM.getResult<HandlesSecrets>(F) << '\n';
    return PreservedAnalyses::all();
}

} // end namespace llvm