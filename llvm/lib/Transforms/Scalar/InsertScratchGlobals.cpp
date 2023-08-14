//===- InsertScratchGlobals.cpp
//-------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Scalar/InsertScratchGlobals.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Scalar.h"

#include <vector>
#include <algorithm>

using namespace llvm;

#define DEBUG_TYPE "isgl"

static cl::opt<bool> EnableGlobalScratch("global-scratch", cl::init(false),
                                         cl::Hidden);

static cl::opt<bool> DynStatDecl("x86-dyn-stat-decl", cl::init(false));
// TODO: This flag is not available in the x86 pass, why?
// Not required now as we are trying to search this global
// by its name instead of creating a new one
static cl::opt<int> SSize("gs-size", cl::init(200), cl::Hidden);

namespace {

class InsertScratchGlobals {
  Module &F;

public:
  InsertScratchGlobals(Module &F) : F(F) {}
  bool insertFuncDecl();
  bool run();
};

} // end anonymous namespace

bool InsertScratchGlobals::insertFuncDecl() {
  Type *I32 = Type::getInt32Ty(F.getContext());
  Type *Void = Type::getVoidTy(F.getContext());
  F.getOrInsertFunction("updateStats", Void, I32);
}

bool InsertScratchGlobals::run() {
  // if (!EnableGlobalScratch) {
  //   return false;
  // }
  
  for (int i = 0; i < SSize; i++) {
    Type *I64 = Type::getInt64Ty(F.getContext());
    auto *Init = ConstantInt::get(I64, 0);
    GlobalVariable *Scratch =
        new GlobalVariable(F, I64, false, GlobalValue::WeakAnyLinkage, Init);
    Scratch->setName("llvm_stats" + std::to_string(i));
  }

  if (DynStatDecl) {
      /* also insert the dyn hit count stats array */
      Type* I32 = Type::getInt32Ty(F.getContext());
      auto* ArrI32 = ArrayType::get(I32, SSize);
      Module& M = F;

      // new
      M.getOrInsertGlobal("llvm_stats", ArrI32);
  }
  
  // Constant* Zero = ConstantInt::get(I32, 0);
  // std::vector<Constant*> ZeroArr(SSize);
  // std::fill(ZeroArr.begin(), ZeroArr.end(), Zero);

  // ArrayRef<Constant*> AR(ZeroArr);
  // Constant* Init = ConstantArray::get(ArrI32, AR);

  // auto IsInvalidCIdentifierLetter = [](const char& letter) {
  //     bool is_valid  = letter == '_' || std::isalnum(letter);
  //     return !is_valid;
  // };

  // std::string module_name = M.getName().str();
  // std::replace_if(module_name.begin(), module_name.end(),
  // 		  IsInvalidCIdentifierLetter, '_');
  // std::string global_name = "llvm_stats_" + module_name;

  // if (NULL == M.getNamedValue(module_name)) {
  //     GlobalVariable* HitCountsArr = 
  // 	  new GlobalVariable(M, ArrI32, false, GlobalValue::WeakAnyLinkage, Init,
  // 			     global_name); 
  //     HitCountsArr->setName(global_name);
  // }
  
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
    //  if (skipModule(F))
    //    return false;
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
