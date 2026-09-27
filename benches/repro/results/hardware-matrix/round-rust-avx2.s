.intel_syntax noprefix
.LBB23_1:
	vpshufd ymm3, ymm13, 78
	vpxor ymm4, ymm12, ymm0
	vpxor ymm5, ymm15, ymm2
	vpxor ymm4, ymm4, ymm5
	vpxor ymm4, ymm4, ymm1
	vpermq ymm5, ymm4, 147
	vpxor ymm3, ymm13, ymm3
	vpermq ymm6, ymm3, 78
	vpsrlq ymm7, ymm4, 63
	vpaddq ymm4, ymm4, ymm4
	vpor ymm4, ymm4, ymm7
	vpxor xmm7, xmm5, xmm4
	vpbroadcastq ymm7, xmm7
	vpxor ymm3, ymm14, ymm3
	vpxor ymm3, ymm3, ymm6
	vpsrlq ymm6, ymm3, 63
	vpaddq ymm8, ymm3, ymm3
	vpor ymm6, ymm8, ymm6
	vpxor ymm8, ymm13, ymm7
	vpxor ymm14, ymm14, ymm7
	vpermq ymm4, ymm4, 249
	vpblendd ymm4, ymm4, ymm6, 192
	vpblendd ymm3, ymm5, ymm3, 3
	vpxor ymm4, ymm3, ymm4
	vpsrlvq ymm3, ymm8, ymmword ptr [rip + .LCPI23_2]
	vpsllvq ymm5, ymm8, ymmword ptr [rip + .LCPI23_3]
	vpor ymm3, ymm5, ymm3
	vpxor ymm0, ymm0, ymm4
	vpsrlvq ymm5, ymm0, ymmword ptr [rip + .LCPI23_4]
	vpsllvq ymm0, ymm0, ymmword ptr [rip + .LCPI23_5]
	vpor ymm13, ymm0, ymm5
	vpxor ymm0, ymm15, ymm4
	vpsrlvq ymm5, ymm0, ymmword ptr [rip + .LCPI23_6]
	vpsllvq ymm0, ymm0, ymmword ptr [rip + .LCPI23_7]
	vpor ymm5, ymm0, ymm5
	vpxor ymm0, ymm2, ymm4
	vpsrlvq ymm2, ymm0, ymmword ptr [rip + .LCPI23_8]
	vpsllvq ymm0, ymm0, ymmword ptr [rip + .LCPI23_9]
	vpor ymm6, ymm0, ymm2
	vpxor ymm0, ymm1, ymm4
	vpermq ymm15, ymm3, 141
	vpermq ymm2, ymm13, 141
	vpsrlvq ymm1, ymm0, ymmword ptr [rip + .LCPI23_10]
	vpsllvq ymm0, ymm0, ymmword ptr [rip + .LCPI23_11]
	vpor ymm0, ymm0, ymm1
	vpxor ymm4, ymm12, ymm4
	vpermq ymm12, ymm5, 27
	vpermq ymm1, ymm6, 114
	vpsrlvq ymm5, ymm4, ymm10
	vpsllvq ymm4, ymm4, ymm11
	vpor ymm5, ymm4, ymm5
	vpblendd ymm4, ymm2, ymm15, 240
	vpunpckhqdq ymm7, ymm6, ymm12
	vpblendd ymm7, ymm4, ymm7, 60
	vperm2i128 ymm8, ymm6, ymm12, 49
	vpblendd ymm4, ymm8, ymm4, 60
	vpandn ymm7, ymm7, ymm4
	vpunpcklqdq ymm4, ymm2, ymm6
	vpblendd ymm6, ymm5, ymm12, 240
	vpblendd ymm4, ymm6, ymm4, 60
	vpunpckhqdq ymm8, ymm13, ymm1
	vpblendd ymm6, ymm8, ymm6, 60
	vpandn ymm4, ymm4, ymm6
	vpblendd ymm6, ymm1, ymm5, 240
	vperm2i128 ymm8, ymm3, ymm12, 49
	vpblendd ymm8, ymm6, ymm8, 60
	vpunpcklqdq ymm9, ymm12, ymm3
	vpblendd ymm6, ymm9, ymm6, 60
	vpxor ymm4, ymm15, ymm4
	vpandn ymm6, ymm8, ymm6
	vpblendd ymm8, ymm15, ymm1, 240
	vperm2i128 ymm9, ymm13, ymm5, 49
	vpblendd ymm9, ymm8, ymm9, 60
	vpunpcklqdq ymm13, ymm5, ymm13
	vpblendd ymm8, ymm13, ymm8, 60
	vpandn ymm8, ymm9, ymm8
	vpxor ymm13, ymm7, ymm5
	vpxor ymm15, ymm6, ymm2
	vpxor ymm6, ymm8, ymm12
	vpblendd ymm2, ymm12, ymm2, 240
	vinserti128 ymm7, ymm5, xmm3, 1
	vpunpckhqdq ymm3, ymm3, ymm5
	vpblendd ymm5, ymm2, ymm7, 60
	vpblendd ymm2, ymm3, ymm2, 60
	vpandn ymm2, ymm5, ymm2
	vpxor ymm1, ymm2, ymm1
	vpermq ymm2, ymm0, 249
	vpblendd ymm2, ymm2, ymm14, 192
	vpermq ymm3, ymm0, 46
	vpblendd ymm3, ymm3, ymm14, 48
	vpandn ymm2, ymm2, ymm3
	vpxor ymm12, ymm2, ymm0
	vpshufd xmm2, xmm0, 238
	vpandn ymm0, ymm0, ymm2
	vmovq xmm2, qword ptr [rcx + rax]
	vpxor xmm0, xmm0, xmm2
	vpbroadcastq ymm0, xmm0
	vpxor ymm14, ymm14, ymm0
	add rcx, 8
	vpermq ymm0, ymm4, 27
	vpermq ymm2, ymm6, 141
	vpermq ymm1, ymm1, 114
	cmp rcx, 192
	jne .LBB23_1
