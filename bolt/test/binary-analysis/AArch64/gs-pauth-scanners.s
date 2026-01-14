// RUN: %clang %cflags -march=armv8.3-a %s -o %t.exe

// Select single detector:

// RUN: llvm-bolt-binary-analysis --scanners=pauth-pac-ret      %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=PACRET                                --implicit-check-not="found in function" %s
// RUN: llvm-bolt-binary-analysis --scanners=pauth-tail-calls   %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=TAIL-CALLS-FPAC,TAIL-CALLS-NOFPAC     --implicit-check-not="found in function" %s
// RUN: llvm-bolt-binary-analysis --scanners=pauth-forward-cf   %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=FORWARD-CF                            --implicit-check-not="found in function" %s
// RUN: llvm-bolt-binary-analysis --scanners=pauth-sign-oracles %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=SIGN-ORACLES-FPAC,SIGN-ORACLES-NOFPAC --implicit-check-not="found in function" %s
// RUN: llvm-bolt-binary-analysis --scanners=pauth-auth-oracles %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=AUTH-ORACLES                          --implicit-check-not="found in function" %s

// Select list of detectors:
// RUN: llvm-bolt-binary-analysis --scanners=pauth-pac-ret,pauth-forward-cf %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=PACRET,FORWARD-CF --implicit-check-not="found in function" %s
// RUN: llvm-bolt-binary-analysis --scanners=pauth-pac-ret,pauth-all %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=PACRET,TAIL-CALLS-FPAC,TAIL-CALLS-NOFPAC,FORWARD-CF,SIGN-ORACLES-FPAC,SIGN-ORACLES-NOFPAC,AUTH-ORACLES --implicit-check-not="found in function" %s

// Select "all" options:
// RUN: llvm-bolt-binary-analysis --scanners=pauth-all %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=PACRET,TAIL-CALLS-FPAC,TAIL-CALLS-NOFPAC,FORWARD-CF,SIGN-ORACLES-FPAC,SIGN-ORACLES-NOFPAC,AUTH-ORACLES --implicit-check-not="found in function" %s
// RUN: llvm-bolt-binary-analysis --scanners=all %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=PACRET,TAIL-CALLS-FPAC,TAIL-CALLS-NOFPAC,FORWARD-CF,SIGN-ORACLES-FPAC,SIGN-ORACLES-NOFPAC,AUTH-ORACLES --implicit-check-not="found in function" %s

// Test FPAC handling:
// RUN: llvm-bolt-binary-analysis --scanners=pauth-all --auth-traps-on-failure %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=PACRET,TAIL-CALLS-FPAC,FORWARD-CF,SIGN-ORACLES-FPAC --implicit-check-not="found in function" %s
// RUN: llvm-bolt-binary-analysis --scanners=pauth-auth-oracles --auth-traps-on-failure %t.exe 2>&1 | \
// RUN:     FileCheck --check-prefixes=NO-REPORTS %s

// NO-REPORTS-NOT: found in function

        .text

        .globl  callee
        .type   callee,@function
callee:
        ret
        .size callee, .-callee

        .globl  bad_pacret
        .type   bad_pacret,@function
bad_pacret:
// PACRET: GS-PAUTH: non-protected ret found in function bad_pacret
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp

        ldp     x29, x30, [sp], #16
        ret
        .size bad_pacret, .-bad_pacret

        .globl  bad_tail_call_fpac
        .type   bad_tail_call_fpac,@function
bad_tail_call_fpac:
// TAIL-CALLS-FPAC: GS-PAUTH: untrusted link register found before tail call in function bad_tail_call_fpac
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp

        ldp     x29, x30, [sp], #16
        b       callee
        .size bad_tail_call_fpac, .-bad_tail_call_fpac

        .globl  bad_tail_call_nofpac
        .type   bad_tail_call_nofpac,@function
bad_tail_call_nofpac:
// TAIL-CALLS-NOFPAC: GS-PAUTH: untrusted link register found before tail call in function bad_tail_call_nofpac
// AUTH-ORACLES:      GS-PAUTH: authentication oracle found in function bad_tail_call_nofpac
        paciasp
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp

        ldp     x29, x30, [sp], #16
        autiasp
        b       callee
        .size bad_tail_call_nofpac, .-bad_tail_call_nofpac

        .globl  bad_call
        .type   bad_call,@function
bad_call:
// FORWARD-CF: GS-PAUTH: non-protected call found in function bad_call
        br      x0
        .size bad_call, .-bad_call

        .globl  bad_signing_oracle_fpac
        .type   bad_signing_oracle_fpac,@function
bad_signing_oracle_fpac:
// SIGN-ORACLES-FPAC: GS-PAUTH: signing oracle found in function bad_signing_oracle_fpac
        pacda   x0, x1
        ret
        .size bad_signing_oracle_fpac, .-bad_signing_oracle_fpac

        .globl  bad_signing_oracle_nofpac
        .type   bad_signing_oracle_nofpac,@function
bad_signing_oracle_nofpac:
// SIGN-ORACLES-NOFPAC: GS-PAUTH: signing oracle found in function bad_signing_oracle_nofpac
// AUTH-ORACLES:        GS-PAUTH: authentication oracle found in function bad_signing_oracle_nofpac
        autda   x0, x1
        pacdb   x0, x1
        ret
        .size bad_signing_oracle_nofpac, .-bad_signing_oracle_nofpac

        .globl  bad_auth_oracle
        .type   bad_auth_oracle,@function
bad_auth_oracle:
// AUTH-ORACLES: GS-PAUTH: authentication oracle found in function bad_auth_oracle
        autda   x0, x1
        ret
        .size bad_auth_oracle, .-bad_auth_oracle
