//===- InsertCompSimpTestFunctions.cpp
//-------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Scalar/InsertCompSimpTestFunctions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Scalar.h"
#include <fstream>

using namespace llvm;

#define DEBUG_TYPE "x86cstest"

static cl::opt<bool> EnableCompSimpTest("x86-cs-test", cl::init(false),
                                        cl::Hidden);

namespace {

class InsertCompSimpTestFunctions {
  Module &F;
  std::vector<std::string> Insts;

public:
  InsertCompSimpTestFunctions(Module &F) : F(F) {}
  void readIntoList(std::string Path);
  void createFunction(std::string Inst);
  void createSilentStoresFunction(std::string Inst);
  bool run();
};

} // end anonymous namespace

void InsertCompSimpTestFunctions::createFunction(std::string Inst) {
  llvm::Function *CompSimpTest = llvm::Function::Create(
      FunctionType::get(Type::getVoidTy(F.getContext()), false),
      GlobalVariable::ExternalLinkage, 0, "x86compsimptest_" + Inst, &F);
  BasicBlock *EntryBB =
      BasicBlock::Create(F.getContext(), "entry", CompSimpTest);
  IRBuilder<> Builder(EntryBB);
  // Builder.CreateRet(ConstantInt::get(Type::getInt64Ty(F.getContext()), 1));
  Builder.CreateRetVoid();
}

void InsertCompSimpTestFunctions::createSilentStoresFunction(std::string Inst) {
  llvm::Function *SilentStoresTest = llvm::Function::Create(
      FunctionType::get(Type::getVoidTy(F.getContext()), false),
      GlobalVariable::ExternalLinkage, 0, "x86silentstorestest_" + Inst, &F);
  BasicBlock *EntryBB =
    BasicBlock::Create(F.getContext(), "entry", SilentStoresTest);
  IRBuilder<> Builder(EntryBB);
  // Builder.CreateRet(ConstantInt::get(Type::getInt64Ty(F.getContext()), 1));
  Builder.CreateRetVoid();
}

void InsertCompSimpTestFunctions::readIntoList(std::string Path) {
  std::vector<std::string> CSInsts{
      "ADD64ri8",  "ADD64ri32", 
      "ADD64rm",   "ADD64rr",   "AND8ri",    "AND64rm",
      "ADD32rr",   "ADD32ri8",  "ADD32i32", "ADD32ri",
      "ADD8rm",    "AND64rr",   "AND64i32",  "AND64ri32", "ADD8ri",
      "AND64ri8",  "AND32rr",   "AND32ri8",  "AND32ri",   "AND32i32",
      "OR64rr",    "OR64rm",    "OR64ri8",   "OR32rr",    "OR32ri8",
      "MUL64m",    "IMUL32rm",  "XOR64rr",   "XOR64rm",
      "XOR32rr",   "XOR32rm",   "XOR32ri8",  "XOR8rr",
      "XOR8rm",    "SUB64rr",   "SUB64rm",   "SUB32rr",   "TEST32rr",
      "AND8rr",    "TEST8ri",   "TEST8i8",   "SHL8rCL",
      "SHR8ri",    "SAR8ri",    "SHR32ri",   "SHR32r1",   "SHR64r1",
      "SHL32rCL",  "SHL32ri",   "SAR64ri",   "SHR64ri",   "XOR32ri",
      "SHL64ri",   "AND16rr",   "OR8rr",     "OR16rr",    "XOR16rr",
      "SUB8rr",    "LEA64r",    "OR8ri",
      "ADD32rm",   "SHR32rCL",  "SHR16rCL",  "MUL32r",
      "CMP64rr",   "CMP64rm",   "CMP32rr",   "CMP32rm",   "MUL64r",
      "IMUL32rr",  "IMUL64rr",  "IMUL64rm",  "IMUL64rri8",
      "IMUL64rri32", "IMUL64rmi32",
      "LEA64_32r", "TEST8mi", "PADDDrr", "PADDDrm", "PADDQrr",
      "PADDQrm",
  };
  
  std::vector<std::string> SSInsts{
      "ADD64mr", "XOR64mr", "ADD64mi32", "ADD32mi8", "ADD64mi8",
      "MOV8mr_NOREX", "MOV8mr", "MOV8mi", "ADD8mr", "ADD32mr",
      "AND8mi", "AND32mr", "PUSH64i8", "PUSH64rmm", "PUSH64r",
  };
  
  for (auto S : CSInsts) {
    createFunction(S + "_original");
    createFunction(S + "_transformed");
  }

  for (auto S : SSInsts) {
    createSilentStoresFunction(S + "_original");
    createSilentStoresFunction(S + "_transformed");
  }
}

bool InsertCompSimpTestFunctions::run() {
  if (!EnableCompSimpTest) {
    return false;
  }
  readIntoList("../../Target/X86/X86CompSimpMap.csv");
  return false;
}

PreservedAnalyses
InsertCompSimpTestFunctionsPass::run(Module &F, ModuleAnalysisManager &FAM) {
  InsertCompSimpTestFunctions(F).run();
  return PreservedAnalyses::all();
}

namespace {

struct InsertCompSimpTestFunctionsLegacyPass : public ModulePass {
  static char ID; // Pass identification, replacement for typeid

  InsertCompSimpTestFunctionsLegacyPass() : ModulePass(ID) {
    initializeInsertCompSimpTestFunctionsLegacyPassPass(
        *PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &F) override {
    //  if (skipModule(F))
    //    return false;
    return InsertCompSimpTestFunctions(F).run();
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }
};

} // end anonymous namespace

char InsertCompSimpTestFunctionsLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(InsertCompSimpTestFunctionsLegacyPass, "isgl",
                      "add functions to test comp simp", false, false)
INITIALIZE_PASS_END(InsertCompSimpTestFunctionsLegacyPass, "isgl",
                    "add functions to test comp simp", false, false)

ModulePass *llvm::createInsertCompSimpTestFunctionsPass() {
  return new InsertCompSimpTestFunctionsLegacyPass();
}
