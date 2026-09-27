.Loop_avx2:
	######################################### Theta
	vpshufd		$78,%ymm2,%ymm13
	vpxor		%ymm3,%ymm5,%ymm12
	vpxor		%ymm6,%ymm4,%ymm9
	vpxor		%ymm1,%ymm12,%ymm12
	vpxor		%ymm9,%ymm12,%ymm12		# C[1..4]

	vpermq		$147,%ymm12,%ymm11
	vpxor		%ymm2,%ymm13,%ymm13
	vpermq		$78,%ymm13,%ymm7

	vpsrlq		$63,%ymm12,%ymm8
	vpaddq		%ymm12,%ymm12,%ymm9
	vpor		%ymm9,%ymm8,%ymm8	# ROL64(C[1..4],1)

	vpermq		$57,%ymm8,%ymm15
	vpxor		%ymm11,%ymm8,%ymm14
	vpermq		$0,%ymm14,%ymm14	# D[0..0] = ROL64(C[1],1) ^ C[4]

	vpxor		%ymm0,%ymm13,%ymm13
	vpxor		%ymm7,%ymm13,%ymm13		# C[0..0]

	vpsrlq		$63,%ymm13,%ymm7
	vpaddq		%ymm13,%ymm13,%ymm8
	vpor		%ymm7,%ymm8,%ymm8	# ROL64(C[0..0],1)

	vpxor		%ymm14,%ymm2,%ymm2		# ^= D[0..0]
	vpxor		%ymm14,%ymm0,%ymm0		# ^= D[0..0]

	vpblendd	$192,%ymm8,%ymm15,%ymm15
	vpblendd	$3,%ymm13,%ymm11,%ymm11
	vpxor		%ymm11,%ymm15,%ymm15		# D[1..4] = ROL64(C[2..4,0),1) ^ C[0..3]

	######################################### Rho + Pi + pre-Chi shuffle
	vpsllvq		0*32-96(%r8),%ymm2,%ymm10
	vpsrlvq		0*32-96(%r9),%ymm2,%ymm2
	vpor		%ymm10,%ymm2,%ymm2

	 vpxor		%ymm15,%ymm3,%ymm3		# ^= D[1..4] from Theta
	vpsllvq		2*32-96(%r8),%ymm3,%ymm11
	vpsrlvq		2*32-96(%r9),%ymm3,%ymm3
	vpor		%ymm11,%ymm3,%ymm3

	 vpxor		%ymm15,%ymm4,%ymm4		# ^= D[1..4] from Theta
	vpsllvq		3*32-96(%r8),%ymm4,%ymm12
	vpsrlvq		3*32-96(%r9),%ymm4,%ymm4
	vpor		%ymm12,%ymm4,%ymm4

	 vpxor		%ymm15,%ymm5,%ymm5		# ^= D[1..4] from Theta
	vpsllvq		4*32-96(%r8),%ymm5,%ymm13
	vpsrlvq		4*32-96(%r9),%ymm5,%ymm5
	vpor		%ymm13,%ymm5,%ymm5

	 vpxor		%ymm15,%ymm6,%ymm6		# ^= D[1..4] from Theta
	 vpermq		$141,%ymm2,%ymm10	# %ymm2 -> future %ymm3
	 vpermq		$141,%ymm3,%ymm11	# %ymm3 -> future %ymm4
	vpsllvq		5*32-96(%r8),%ymm6,%ymm14
	vpsrlvq		5*32-96(%r9),%ymm6,%ymm8
	vpor		%ymm14,%ymm8,%ymm8	# %ymm6 -> future %ymm1

	 vpxor		%ymm15,%ymm1,%ymm1		# ^= D[1..4] from Theta
	 vpermq		$27,%ymm4,%ymm12	# %ymm4 -> future %ymm5
	 vpermq		$114,%ymm5,%ymm13	# %ymm5 -> future %ymm6
	vpsllvq		1*32-96(%r8),%ymm1,%ymm15
	vpsrlvq		1*32-96(%r9),%ymm1,%ymm9
	vpor		%ymm15,%ymm9,%ymm9	# %ymm1 -> future %ymm2

	######################################### Chi
	vpsrldq		$8,%ymm8,%ymm14
	vpandn		%ymm14,%ymm8,%ymm7	# tgting  [0][0] [0][0] [0][0] [0][0]

	vpblendd	$12,%ymm13,%ymm9,%ymm3	#               [4][4] [2][0]
	vpblendd	$12,%ymm9,%ymm11,%ymm15	#               [4][0] [2][1]
	 vpblendd	$12,%ymm11,%ymm10,%ymm5	#               [4][2] [2][4]
	 vpblendd	$12,%ymm10,%ymm9,%ymm14	#               [4][3] [2][0]
	vpblendd	$48,%ymm11,%ymm3,%ymm3	#        [1][3] [4][4] [2][0]
	vpblendd	$48,%ymm12,%ymm15,%ymm15	#        [1][4] [4][0] [2][1]
	 vpblendd	$48,%ymm9,%ymm5,%ymm5	#        [1][0] [4][2] [2][4]
	 vpblendd	$48,%ymm13,%ymm14,%ymm14	#        [1][1] [4][3] [2][0]
	vpblendd	$192,%ymm12,%ymm3,%ymm3	# [3][2] [1][3] [4][4] [2][0]
	vpblendd	$192,%ymm13,%ymm15,%ymm15	# [3][3] [1][4] [4][0] [2][1]
	 vpblendd	$192,%ymm13,%ymm5,%ymm5	# [3][3] [1][0] [4][2] [2][4]
	 vpblendd	$192,%ymm11,%ymm14,%ymm14	# [3][4] [1][1] [4][3] [2][0]
	vpandn		%ymm15,%ymm3,%ymm3		# tgting  [3][1] [1][2] [4][3] [2][4]
	 vpandn		%ymm14,%ymm5,%ymm5		# tgting  [3][2] [1][4] [4][1] [2][3]

	vpblendd	$12,%ymm9,%ymm12,%ymm6	#               [4][0] [2][3]
	vpblendd	$12,%ymm12,%ymm10,%ymm15	#               [4][1] [2][4]
	 vpxor		%ymm10,%ymm3,%ymm3
	vpblendd	$48,%ymm10,%ymm6,%ymm6	#        [1][2] [4][0] [2][3]
	vpblendd	$48,%ymm11,%ymm15,%ymm15	#        [1][3] [4][1] [2][4]
	 vpxor		%ymm12,%ymm5,%ymm5
	vpblendd	$192,%ymm11,%ymm6,%ymm6	# [3][4] [1][2] [4][0] [2][3]
	vpblendd	$192,%ymm9,%ymm15,%ymm15	# [3][0] [1][3] [4][1] [2][4]
	vpandn		%ymm15,%ymm6,%ymm6		# tgting  [3][3] [1][1] [4][4] [2][2]
	vpxor		%ymm13,%ymm6,%ymm6

	  vpermq	$30,%ymm8,%ymm4		# [0][1] [0][2] [0][4] [0][3]
	  vpblendd	$48,%ymm0,%ymm4,%ymm15	# [0][1] [0][0] [0][4] [0][3]
	  vpermq	$57,%ymm8,%ymm1		# [0][1] [0][4] [0][3] [0][2]
	  vpblendd	$192,%ymm0,%ymm1,%ymm1	# [0][0] [0][4] [0][3] [0][2]
	  vpandn	%ymm15,%ymm1,%ymm1		# tgting  [0][4] [0][3] [0][2] [0][1]

	vpblendd	$12,%ymm12,%ymm11,%ymm2	#               [4][1] [2][1]
	vpblendd	$12,%ymm11,%ymm13,%ymm14	#               [4][2] [2][2]
	vpblendd	$48,%ymm13,%ymm2,%ymm2	#        [1][1] [4][1] [2][1]
	vpblendd	$48,%ymm10,%ymm14,%ymm14	#        [1][2] [4][2] [2][2]
	vpblendd	$192,%ymm10,%ymm2,%ymm2	# [3][1] [1][1] [4][1] [2][1]
	vpblendd	$192,%ymm12,%ymm14,%ymm14	# [3][2] [1][2] [4][2] [2][2]
	vpandn		%ymm14,%ymm2,%ymm2		# tgting  [3][0] [1][0] [4][0] [2][0]
	vpxor		%ymm9,%ymm2,%ymm2

	 vpermq		$0,%ymm7,%ymm7	# [0][0] [0][0] [0][0] [0][0]
	 vpermq		$27,%ymm3,%ymm3	# post-Chi shuffle
	 vpermq		$141,%ymm5,%ymm5
	 vpermq		$114,%ymm6,%ymm6

	vpblendd	$12,%ymm10,%ymm13,%ymm4	#               [4][3] [2][2]
	vpblendd	$12,%ymm13,%ymm12,%ymm14	#               [4][4] [2][3]
	vpblendd	$48,%ymm12,%ymm4,%ymm4	#        [1][4] [4][3] [2][2]
	vpblendd	$48,%ymm9,%ymm14,%ymm14	#        [1][0] [4][4] [2][3]
	vpblendd	$192,%ymm9,%ymm4,%ymm4	# [3][0] [1][4] [4][3] [2][2]
	vpblendd	$192,%ymm10,%ymm14,%ymm14	# [3][1] [1][0] [4][4] [2][3]
	vpandn		%ymm14,%ymm4,%ymm4		# tgting  [3][4] [1][3] [4][2] [2][1]

	vpxor		%ymm7,%ymm0,%ymm0
	vpxor		%ymm8,%ymm1,%ymm1
	vpxor		%ymm11,%ymm4,%ymm4

	######################################### Iota
	vpxor		(%r10),%ymm0,%ymm0
	lea		32(%r10),%r10

	dec		%eax
	jnz		.Loop_avx2
