.intel_syntax noprefix
.LBB23_1:
	vmovdqa64 xmm24, xmm9
	vpternlogq xmm24, xmm23, xmm18, 150
	vmovdqa64 xmm27, xmm13
	vpternlogq xmm27, xmm16, xmm17, 150
	vmovdqa64 xmm28, xmm8
	vpternlogq xmm28, xmm15, xmm12, 150
	vmovdqa64 xmm25, xmm0
	vpternlogq xmm25, xmm6, xmm21, 150
	vmovdqa64 xmm1, xmm30
	vpternlogq xmm1, xmm10, xmm11, 150
	vpternlogq xmm24, xmm5, xmm7, 150
	vpternlogq xmm27, xmm19, xmm14, 150
	vpternlogq xmm28, xmm2, xmm22, 150
	vpternlogq xmm1, xmm26, xmm3, 150
	vpternlogq xmm25, xmm31, xmm4, 150
	vprolq xmm20, xmm24, 1
	vprolq xmm29, xmm1, 1
	vpternlogq xmm13, xmm28, xmm20, 150
	vpternlogq xmm16, xmm28, xmm20, 150
	vpternlogq xmm17, xmm28, xmm20, 150
	vpternlogq xmm19, xmm28, xmm20, 150
	vpternlogq xmm14, xmm28, xmm20, 150
	vprolq xmm20, xmm27, 1
	vpternlogq xmm0, xmm24, xmm29, 150
	vpternlogq xmm21, xmm24, xmm29, 150
	vpternlogq xmm6, xmm24, xmm29, 150
	vpternlogq xmm31, xmm24, xmm29, 150
	vpternlogq xmm24, xmm4, xmm29, 150
	vprolq xmm0, xmm0, 62
	vprolq xmm29, xmm31, 15
	vpternlogq xmm12, xmm1, xmm20, 150
	vpternlogq xmm8, xmm1, xmm20, 150
	vpternlogq xmm15, xmm1, xmm20, 150
	vpternlogq xmm2, xmm1, xmm20, 150
	vpternlogq xmm1, xmm22, xmm20, 150
	vprolq xmm20, xmm25, 1
	vprolq xmm22, xmm28, 1
	vmovdqa xmmword ptr [rsp - 24], xmm0
	vprolq xmm0, xmm8, 27
	vprolq xmm1, xmm1, 14
	vprolq xmm4, xmm12, 39
	vmovdqa xmm8, xmm13
	vprolq xmm12, xmm14, 18
	vpternlogq xmm9, xmm27, xmm20, 150
	vpternlogq xmm30, xmm25, xmm22, 150
	vpternlogq xmm26, xmm25, xmm22, 150
	vpternlogq xmm5, xmm27, xmm20, 150
	vpternlogq xmm10, xmm25, xmm22, 150
	vpternlogq xmm23, xmm27, xmm20, 150
	vpternlogq xmm11, xmm25, xmm22, 150
	vpternlogq xmm18, xmm27, xmm20, 150
	vpternlogq xmm7, xmm27, xmm20, 150
	vprolq xmm20, xmm6, 6
	vpternlogq xmm25, xmm3, xmm22, 150
	vprolq xmm6, xmm17, 3
	vprolq xmm27, xmm15, 20
	vprolq xmm3, xmm19, 41
	vprolq xmm15, xmm24, 61
	vprolq xmm9, xmm9, 1
	vprolq xmm28, xmm30, 28
	vprolq xmm30, xmm26, 21
	vprolq xmm26, xmm10, 55
	vprolq xmm10, xmm5, 45
	vmovdqa xmmword ptr [rsp - 40], xmm0
	vprolq xmm0, xmm21, 43
	vmovdqa64 xmm21, xmm13
	vprolq xmm31, xmm18, 10
	vprolq xmm22, xmm7, 2
	vmovdqa xmm7, xmmword ptr [rsp - 40]
	vmovdqa64 xmm18, xmm20
	vmovdqa xmmword ptr [rsp - 56], xmm9
	vprolq xmm9, xmm23, 44
	vmovdqa64 xmm23, xmm27
	vpternlogq xmm23, xmm6, xmm10, 210
	vmovdqa xmm5, xmmword ptr [rsp - 56]
	vpternlogq xmm21, xmm9, xmm0, 210
	vpternlogq xmm8, xmm1, xmm9, 198
	vpternlogq xmm9, xmm0, xmm30, 210
	vpternlogq xmm0, xmm30, xmm1, 210
	vpternlogq xmm30, xmm1, xmm13, 210
	vpxorq xmm13, xmm21, qword ptr [rcx + rax]{1to2}
	vprolq xmm21, xmm11, 25
	vprolq xmm11, xmm2, 8
	vprolq xmm1, xmm16, 36
	vprolq xmm2, xmm25, 56
	vmovdqa64 xmm16, xmm28
	vpternlogq xmm16, xmm27, xmm6, 210
	vpternlogq xmm6, xmm10, xmm15, 210
	vpternlogq xmm10, xmm15, xmm28, 210
	lea rcx, [rcx + 8]
	vpternlogq xmm15, xmm28, xmm27, 210
	vpternlogq xmm18, xmm21, xmm11, 210
	vmovdqa64 xmm19, xmm7
	vpternlogq xmm19, xmm1, xmm31, 210
	vmovdqa64 xmm17, xmm5
	vpternlogq xmm17, xmm20, xmm21, 210
	vpternlogq xmm21, xmm11, xmm12, 210
	vpternlogq xmm11, xmm12, xmm5, 210
	vpternlogq xmm12, xmm5, xmm20, 210
	vmovdqa64 xmm20, xmmword ptr [rsp - 24]
	vmovdqa xmm5, xmm1
	vpternlogq xmm5, xmm31, xmm29, 210
	vpternlogq xmm31, xmm29, xmm2, 210
	vpternlogq xmm29, xmm2, xmm7, 210
	vpternlogq xmm2, xmm7, xmm1, 210
	vmovdqa64 xmm7, xmm26
	vpternlogq xmm7, xmm4, xmm3, 210
	vmovdqa64 xmm14, xmm20
	vpternlogq xmm14, xmm26, xmm4, 210
	vpternlogq xmm4, xmm3, xmm22, 210
	vpternlogq xmm3, xmm22, xmm20, 210
	vpternlogq xmm22, xmm20, xmm26, 210
	vmovdqa64 xmm26, xmm29
	cmp rcx, 192
	jne .LBB23_1
