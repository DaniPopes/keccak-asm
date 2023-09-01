.section .text.KeccakF1600,"ax",@progbits
	.globl	KeccakF1600
	.p2align	4, 0x90
	.type	KeccakF1600,@function
KeccakF1600:

	.cfi_startproc
	sub rsp, 72
	.cfi_def_cfa_offset 80

	lea rax, [rip + core::array::<impl core::fmt::Debug for [T; N]>::fmt]
	#APP
	mov r11, rsp
	lea rdi, [rdi + 96]
	shr rcx, 3
	vzeroupper
	vpbroadcastq ymm0, qword ptr [rdi - 96]
	vpxor ymm7, ymm7, ymm7
	vmovdqu ymm1, ymmword ptr [rdi - 88]
	vmovdqu ymm2, ymmword ptr [rdi - 56]
	vmovdqu ymm3, ymmword ptr [rdi - 24]
	vmovdqu ymm4, ymmword ptr [rdi + 8]
	vmovdqu ymm5, ymmword ptr [rdi + 40]
	vmovdqu ymm6, ymmword ptr [rdi + 72]
	mov rax, rcx
	mov r8, qword ptr [rdi - 120]
	call __KeccakF1600
	#NO_APP

	vmovsd qword ptr [rsp + 8], xmm0
	lea rsi, [rip + .L__unnamed_2]
	lea rdi, [rsp + 24]

	mov qword ptr [rsp + 16], rax

	lea rax, [rip + .L__unnamed_3]

	mov qword ptr [rsp + 24], rax
	lea rax, [rsp + 8]

	mov qword ptr [rsp + 32], 1
	mov qword ptr [rsp + 56], 0
	mov qword ptr [rsp + 40], rax
	mov qword ptr [rsp + 48], 1

	call qword ptr [rip + core::panicking::panic_fmt@GOTPCREL]
	ud2

