.Loop_avx512:

	vmovdqa64	%zmm0,%zmm5
	vpternlogq	$0x96,%zmm2,%zmm1,%zmm0
	vpternlogq	$0x96,%zmm4,%zmm3,%zmm0

	vprolq	$1,%zmm0,%zmm6
	vpermq	%zmm0,%zmm13,%zmm0
	vpermq	%zmm6,%zmm16,%zmm6

	vpternlogq	$0x96,%zmm0,%zmm6,%zmm5
	vpternlogq	$0x96,%zmm0,%zmm6,%zmm1
	vpternlogq	$0x96,%zmm0,%zmm6,%zmm2
	vpternlogq	$0x96,%zmm0,%zmm6,%zmm3
	vpternlogq	$0x96,%zmm0,%zmm6,%zmm4


	vprolvq	%zmm22,%zmm5,%zmm0
	vprolvq	%zmm23,%zmm1,%zmm1
	vprolvq	%zmm24,%zmm2,%zmm2
	vprolvq	%zmm25,%zmm3,%zmm3
	vprolvq	%zmm26,%zmm4,%zmm4


	vpermq	%zmm0,%zmm17,%zmm0
	vpermq	%zmm1,%zmm18,%zmm1
	vpermq	%zmm2,%zmm19,%zmm2
	vpermq	%zmm3,%zmm20,%zmm3
	vpermq	%zmm4,%zmm21,%zmm4


	vmovdqa64	%zmm0,%zmm5
	vmovdqa64	%zmm1,%zmm6
	vpternlogq	$0xD2,%zmm2,%zmm1,%zmm0
	vpternlogq	$0xD2,%zmm3,%zmm2,%zmm1
	vpternlogq	$0xD2,%zmm4,%zmm3,%zmm2
	vpternlogq	$0xD2,%zmm5,%zmm4,%zmm3
	vpternlogq	$0xD2,%zmm6,%zmm5,%zmm4


	vpxorq	(%r10),%zmm0,%zmm0{%k1}
	leaq	16(%r10),%r10


	vpblendmq	%zmm2,%zmm1,%zmm6{%k2}
	vpblendmq	%zmm3,%zmm2,%zmm7{%k2}
	vpblendmq	%zmm4,%zmm3,%zmm8{%k2}
	vpblendmq	%zmm1,%zmm0,%zmm5{%k2}
	vpblendmq	%zmm0,%zmm4,%zmm9{%k2}

	vpblendmq	%zmm3,%zmm6,%zmm6{%k3}
	vpblendmq	%zmm4,%zmm7,%zmm7{%k3}
	vpblendmq	%zmm2,%zmm5,%zmm5{%k3}
	vpblendmq	%zmm0,%zmm8,%zmm8{%k3}
	vpblendmq	%zmm1,%zmm9,%zmm9{%k3}

	vpblendmq	%zmm4,%zmm6,%zmm6{%k4}
	vpblendmq	%zmm3,%zmm5,%zmm5{%k4}
	vpblendmq	%zmm0,%zmm7,%zmm7{%k4}
	vpblendmq	%zmm1,%zmm8,%zmm8{%k4}
	vpblendmq	%zmm2,%zmm9,%zmm9{%k4}

	vpblendmq	%zmm4,%zmm5,%zmm5{%k5}
	vpblendmq	%zmm0,%zmm6,%zmm6{%k5}
	vpblendmq	%zmm1,%zmm7,%zmm7{%k5}
	vpblendmq	%zmm2,%zmm8,%zmm8{%k5}
	vpblendmq	%zmm3,%zmm9,%zmm9{%k5}


	vpermq	%zmm6,%zmm13,%zmm1
	vpermq	%zmm7,%zmm14,%zmm2
	vpermq	%zmm8,%zmm15,%zmm3
	vpermq	%zmm9,%zmm16,%zmm4


	vmovdqa64	%zmm5,%zmm0
	vpternlogq	$0x96,%zmm2,%zmm1,%zmm5
	vpternlogq	$0x96,%zmm4,%zmm3,%zmm5

	vprolq	$1,%zmm5,%zmm6
	vpermq	%zmm5,%zmm13,%zmm5
	vpermq	%zmm6,%zmm16,%zmm6

	vpternlogq	$0x96,%zmm5,%zmm6,%zmm0
	vpternlogq	$0x96,%zmm5,%zmm6,%zmm3
	vpternlogq	$0x96,%zmm5,%zmm6,%zmm1
	vpternlogq	$0x96,%zmm5,%zmm6,%zmm4
	vpternlogq	$0x96,%zmm5,%zmm6,%zmm2


	vprolvq	%zmm27,%zmm0,%zmm0
	vprolvq	%zmm30,%zmm3,%zmm6
	vprolvq	%zmm28,%zmm1,%zmm7
	vprolvq	%zmm31,%zmm4,%zmm8
	vprolvq	%zmm29,%zmm2,%zmm9

	vpermq	%zmm0,%zmm16,%zmm10
	vpermq	%zmm0,%zmm15,%zmm11


	vpxorq	-8(%r10),%zmm0,%zmm0{%k1}


	vpermq	%zmm6,%zmm14,%zmm1
	vpermq	%zmm7,%zmm16,%zmm2
	vpermq	%zmm8,%zmm13,%zmm3
	vpermq	%zmm9,%zmm15,%zmm4


	vpternlogq	$0xD2,%zmm11,%zmm10,%zmm0

	vpermq	%zmm6,%zmm13,%zmm12

	vpternlogq	$0xD2,%zmm6,%zmm12,%zmm1

	vpermq	%zmm7,%zmm15,%zmm5
	vpermq	%zmm7,%zmm14,%zmm7
	vpternlogq	$0xD2,%zmm7,%zmm5,%zmm2


	vpermq	%zmm8,%zmm16,%zmm6
	vpternlogq	$0xD2,%zmm6,%zmm8,%zmm3

	vpermq	%zmm9,%zmm14,%zmm5
	vpermq	%zmm9,%zmm13,%zmm9
	vpternlogq	$0xD2,%zmm9,%zmm5,%zmm4

	decl	%eax
	jnz	.Loop_avx512
