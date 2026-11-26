//go:build amd64 && gc && !purego

#include "textflag.h"

// Seven 128-bit state words remain in registers over the complete block run.
// AESENC performs SubBytes/ShiftRows/MixColumns followed by round-key XOR.
// There are no secret-indexed loads or secret-dependent conditional branches.
TEXT ·roccaSBlocks(SB), NOSPLIT, $0-40
	MOVQ state+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ blocks+24(FP), CX
	MOVQ mode+32(FP), DX
	TESTQ CX, CX
	JE done
	MOVOU 0(AX), X0
	MOVOU 16(AX), X1
	MOVOU 32(AX), X2
	MOVOU 48(AX), X3
	MOVOU 64(AX), X4
	MOVOU 80(AX), X5
	MOVOU 96(AX), X6
loop:
	MOVOU 0(SI), X8
	MOVOU 16(SI), X9
	CMPQ DX, $1
	JE crypt
	CMPQ DX, $2
	JNE update
crypt:
	MOVOU X3, X10
	PXOR X5, X10
	AESENC X0, X10
	PXOR X8, X10
	MOVOU X4, X11
	PXOR X6, X11
	AESENC X2, X11
	PXOR X9, X11
	MOVOU X10, 0(DI)
	MOVOU X11, 16(DI)
	ADDQ $32, DI
	CMPQ DX, $2
	JNE update
	MOVOU X10, X8
	MOVOU X11, X9
update:
	MOVOU X6, X7
	PXOR X1, X7
	// Reverse dependency order preserves every old state word until consumed.
	AESENC X4, X5
	AESENC X3, X4
	AESENC X9, X3
	AESENC X6, X2
	AESENC X0, X1
	AESENC X8, X0
	MOVOU X5, X6
	MOVOU X4, X5
	MOVOU X3, X4
	MOVOU X2, X3
	MOVOU X1, X2
	MOVOU X0, X1
	MOVOU X7, X0
	CMPQ DX, $3
	JE next
	ADDQ $32, SI
next:
	DECQ CX
	JNZ loop
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	MOVOU X2, 32(AX)
	MOVOU X3, 48(AX)
	MOVOU X4, 64(AX)
	MOVOU X5, 80(AX)
	MOVOU X6, 96(AX)
	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	PXOR X5, X5
	PXOR X6, X6
	PXOR X7, X7
	PXOR X8, X8
	PXOR X9, X9
	PXOR X10, X10
	PXOR X11, X11
done:
	RET
