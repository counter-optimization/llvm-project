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
    /* cs tested but not actually needed: 
       {'SUB64rm', 'TEST32rr', 'OR64rm', 'SHR16rCL', 'OR32ri8', 'XOR32ri8', 'MUL32r', 'OR16rr', 'ADD32ri', 'SHL8rCL', 'XOR16rr', 'XOR8rr', 'AND8rr', 'AND16rr'} 
       and ofc 'VPCOMPRESSBZ256rrkz' since it is used in our
       benchmarks as empty test case*/
  std::vector<std::string> CSInsts{
      "OR8i8",      "OR8ri",       "OR8rr",       "OR16rr",    "OR32rr",
      "OR32ri8",     "OR64rr",      "OR64rm",    "OR64ri8",    "OR64ri32",
      "XOR8rr",     "XOR8rm",      "XOR16rr",
      "XOR32rr",    "XOR32rm",     "XOR32ri",     "XOR32ri8",
      "XOR64rr",    "XOR64rm",
      "AND8rr",     "AND8i8",      "AND8ri",      "AND16rr",
      "AND32rr",    "AND32ri",     "AND32ri8",    "AND32i32",
      "AND64rr",    "AND64rm",     "AND64i32",    "AND64ri32", "AND64ri8",
      "TEST8ri",    "TEST8i8",     "TEST8mi",     "TEST32rr",
      
      "SHL8rCL",    "SHL8ri",      "SHL32rCL",    "SHL32ri",   "SHL64ri",
      "SHR8ri",     "SHR32rCL",    "SHR32ri",     "SHR32r1",
      "SHR64r1",    "SHR64ri",
      "SAR8ri",     "SAR64ri",     "SAR32ri",

      "SUB8rr",     "SUB32rr",     "SUB32rm",     "SUB64rr",     "SUB64rm",
      "ADD8rm",     "ADD8ri",
      "ADD32rr",    "ADD32rm",     "ADD32i32",    "ADD32ri8",  "ADD32ri",
      "ADD64rr",    "ADD64i32",    "ADD64ri8",    "ADD64ri32", "ADD64rm",
   
      "LEA64r",     "LEA64_32r",
      "MUL32r",     "MUL64r",      "MUL64m",
      "IMUL32rr",   "IMUL32rm",    "IMUL32rri8",  "IMUL64rr",    "IMUL64rm",
      "IMUL64rri8", "IMUL64rri32", "IMUL64rmi32",
  
      "CMP32rr",    "CMP32rm",     "CMP64rr",     "CMP64rm",   "CMP64mr",
      
      "PADDDrr",    "PADDDrm",     "PADDQrr",     "PADDQrm",
      "VPCOMPRESSBZ256rrkz", /* null test name, generates an empty test */
  };

  /* MOV8mr_HIGHBYTE does not correspond to an actual insn,
     but tests that our transform handles MOV8mr where the 
     register src operand is the high byte of a 16bit sub register
     (i.e., AH, BH, CH, or DH). these have to be handled specially
     since you cannot mix REX-encoded insns--which include any that
     use r10-r15 registers--with AH,BH,CH,DH) */
  std::vector<std::string> SSInsts{
      "ADD64mr", "XOR64mr", "ADD64mi32", "ADD32mi8", "ADD64mi8",
      "MOV8mr_NOREX", "MOV8mr", "MOV8mi", "ADD8mr", "ADD32mr",
      "AND8mi", "AND32mr", "PUSH64i8", "PUSH64rmm", "PUSH64r",
      "MOV32mr", "MOV32mi", "MOV16mr", "MOV16mi", "MOVPDI2DImr",
      "MOV64mi32", "MOV64mr", "PUSH64i32", "MOVAPSmr", "MOVDQAmr",
      "MOVUPSmr", "MOVDQUmr", "SUB32mr", "XOR8mr",
      "MOV8mr_HIGHBYTE", 
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
