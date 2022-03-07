#include "llvm/Analysis/HandlesSecrets.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/InitializePasses.h"

using namespace llvm;

INITIALIZE_PASS(HandlesSecretsWrapperPass, "hs",
            "Results for whether the function operates on variables marked secret",
            false, true)

INITIALIZE_PASS_BEGIN(HandlesSecretsModulePass, "hsm",
            "Results for whether the function operates on variables marked secret",
            false, true)
INITIALIZE_PASS_DEPENDENCY(HandlesSecretsWrapperPass)
INITIALIZE_PASS_END(HandlesSecretsModulePass, "hsm",
            "Results for whether the function operates on variables marked secret",
            false, true)

namespace llvm {

AnalysisKey HandlesSecrets::Key;

// Run over each instruction of the Function. Check for each instruction that
// subclasses CallBase (either a call, callbr, or invoke llvm IR insn) whether
// it is the LLVM intrinsic "llvm.var.annotation" which appears for the GNU style
// attribute: __attribute__((annotation(...))). If it finds one of these annotations,
// it checks to see if the annotation is "secret", i.e., that it was annotated using
// __attribute__((annotation("secret"))).
// The LLVM IR would look something like this:
StringRef HandlesSecrets::run(Function &F, FunctionAnalysisManager &AM) {
    StringRef SecretLabel("secret");
    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        if (auto *CallInsn = dyn_cast<CallBase>(&*I)) {
            if (auto *CalledFunction = CallInsn->getCalledFunction()) {
                if (CalledFunction->isIntrinsic() && CalledFunction->getName() == "llvm.var.annotation") {
                    // At this point, means that we've found an annotation attribute, the rest of this nesting
                    // checks that the annotation attribute is a "secret" annotation attribute courtesy of
                    // https://stackoverflow.com/questions/46206777/identify-annotated-variable-in-an-llvm-pass
                    // The llvm.var.annotation intrinsic has three args: ptr to the variable being annotated,
                    // pointer to the global string annotation, and a pointer to the global filename corresponding
                    // to the llvm ir module 
                    ConstantExpr *ce = cast<ConstantExpr>(CallInsn->getOperand(1));
                    if (ce) {
                        if (ce->getOpcode() == Instruction::GetElementPtr) {
                            if (GlobalVariable *annoteStr =
                                dyn_cast<GlobalVariable>(ce->getOperand(0))) {
                                if (ConstantDataSequential *data =
                                        dyn_cast<ConstantDataSequential>(annoteStr->getInitializer())) {
                                    if (data->isString()) {
                                        StringRef AnnotationLabel = data->getAsString();
                                        if (AnnotationLabel.startswith(SecretLabel)) {
                                            return "true";
                                        }
                                    }
                                }
                            }
                        }
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

HandlesSecretsWrapperPass::HandlesSecretsWrapperPass() : FunctionPass(ID) {
    initializeHandlesSecretsWrapperPassPass(*PassRegistry::getPassRegistry());
}

void HandlesSecretsWrapperPass::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.setPreservesAll();
}

bool HandlesSecretsWrapperPass::runOnFunction(Function &F) {
    StringRef SecretLabel("secret");
    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        if (auto *CallInsn = dyn_cast<CallBase>(&*I)) {
            if (auto *CalledFunction = CallInsn->getCalledFunction()) {
                if (CalledFunction->isIntrinsic() && CalledFunction->getName() == "llvm.var.annotation") {
                    FunctionHandlesSecrets = true;
                    // At this point, means that we've found an annotation attribute, the rest of this nesting
                    // checks that the annotation attribute is a "secret" annotation attribute courtesy of
                    // https://stackoverflow.com/questions/46206777/identify-annotated-variable-in-an-llvm-pass
                    // The llvm.var.annotation intrinsic has three args: ptr to the variable being annotated,
                    // pointer to the global string annotation, and a pointer to the global filename corresponding
                    // to the llvm ir module 
                    ConstantExpr *ce = cast<ConstantExpr>(CallInsn->getOperand(1));
                    if (ce) {
                        if (ce->getOpcode() == Instruction::GetElementPtr) {
                            if (GlobalVariable *annoteStr =
                                dyn_cast<GlobalVariable>(ce->getOperand(0))) {
                                if (ConstantDataSequential *data =
                                        dyn_cast<ConstantDataSequential>(annoteStr->getInitializer())) {
                                    if (data->isString()) {
                                        StringRef AnnotationLabel = data->getAsString();
                                        if (AnnotationLabel.startswith(SecretLabel)) {
                                            FunctionHandlesSecrets = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    FunctionHandlesSecrets = false;
    return false; // Doesn't change IR
}

char HandlesSecretsWrapperPass::ID = 0;
char HandlesSecretsModulePass::ID = 0;



} // end namespace llvm