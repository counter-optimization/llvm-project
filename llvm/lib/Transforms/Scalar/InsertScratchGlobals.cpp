//===- InsertScratchGlobals.cpp
//-------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Scalar/InsertScratchGlobals.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Scalar.h"

using namespace llvm;

#define DEBUG_TYPE "isgl"

static cl::opt<bool> EnableGlobalScratch("global-scratch", cl::init(false),
                                         cl::Hidden);
static cl::opt<int> SSize("gs-size", cl::init(50), cl::Hidden);

namespace {

class InsertScratchGlobals {
  Module &F;

public:
  InsertScratchGlobals(Module &F) : F(F) {}
  bool run();
};

} // end anonymous namespace

bool InsertScratchGlobals::run() {
  Type *I32 = Type::getInt32Ty(F.getContext());
  Type *ArrI32 = ArrayType::get(I32, SSize);
  auto *Init = ConstantAggregateZero::get(ArrI32);
  GlobalVariable *Scratch =
      new GlobalVariable(F, ArrI32, false, GlobalValue::WeakODRLinkage, Init);
  Scratch->setAlignment(Align(16));
  Scratch->setName("llvm_stats");
  return false;
}

PreservedAnalyses InsertScratchGlobalsPass::run(Module &F,
                                                ModuleAnalysisManager &FAM) {
  InsertScratchGlobals(F).run();
  return PreservedAnalyses::all();
}

namespace {

struct InsertScratchGlobalsLegacyPass : public ModulePass {
  static char ID; // Pass identification, replacement for typeid

  InsertScratchGlobalsLegacyPass() : ModulePass(ID) {
    initializeInsertScratchGlobalsLegacyPassPass(
        *PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &F) override {
    if (skipModule(F))
      return false;
    return InsertScratchGlobals(F).run();
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }
};

} // end anonymous namespace

char InsertScratchGlobalsLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(InsertScratchGlobalsLegacyPass, "isgl",
                      "enable global as scratch", false, false)
INITIALIZE_PASS_END(InsertScratchGlobalsLegacyPass, "isgl",
                    "enable global as scratch", false, false)

ModulePass *llvm::createInsertScratchGlobalsPass() {
  return new InsertScratchGlobalsLegacyPass();
}
