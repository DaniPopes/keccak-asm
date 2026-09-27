.Loop_avx512vl:

	vpshufd	$78,%ymm2,%ymm13
	vpxor	%ymm3,%ymm5,%ymm12
	vpxor	%ymm6,%ymm4,%ymm9
	vpternlogq	$0x96,%ymm1,%ymm9,%ymm12

	vpxor	%ymm2,%ymm13,%ymm13
	vpermq	$78,%ymm13,%ymm7

	vpermq	$147,%ymm12,%ymm11
	vprolq	$1,%ymm12,%ymm8

	vpermq	$57,%ymm8,%ymm15
	vpxor	%ymm11,%ymm8,%ymm14
	vpermq	$0,%ymm14,%ymm14

	vpternlogq	$0x96,%ymm7,%ymm0,%ymm13
	vprolq	$1,%ymm13,%ymm8

	vpxor	%ymm14,%ymm0,%ymm0

	vpblendd	$192,%ymm8,%ymm15,%ymm15
	vpblendd	$3,%ymm13,%ymm11,%ymm7


	vpxor	%ymm14,%ymm2,%ymm2
	vprolvq	%ymm16,%ymm2,%ymm2

	vpternlogq	$0x96,%ymm7,%ymm15,%ymm3
	vprolvq	%ymm18,%ymm3,%ymm3

	vpternlogq	$0x96,%ymm7,%ymm15,%ymm4
	vprolvq	%ymm19,%ymm4,%ymm4

	vpternlogq	$0x96,%ymm7,%ymm15,%ymm5
	vprolvq	%ymm20,%ymm5,%ymm5

	vpermq	$141,%ymm2,%ymm10
	vpermq	$141,%ymm3,%ymm11
	vpternlogq	$0x96,%ymm7,%ymm15,%ymm6
	vprolvq	%ymm21,%ymm6,%ymm8

	vpermq	$27,%ymm4,%ymm12
	vpermq	$114,%ymm5,%ymm13
	vpternlogq	$0x96,%ymm7,%ymm15,%ymm1
	vprolvq	%ymm17,%ymm1,%ymm9


	vpblendd	$12,%ymm13,%ymm9,%ymm3
	vpblendd	$12,%ymm9,%ymm11,%ymm15
	vpblendd	$12,%ymm11,%ymm10,%ymm5
	vpblendd	$12,%ymm10,%ymm9,%ymm14
	vpblendd	$48,%ymm11,%ymm3,%ymm3
	vpblendd	$48,%ymm12,%ymm15,%ymm15
	vpblendd	$48,%ymm9,%ymm5,%ymm5
	vpblendd	$48,%ymm13,%ymm14,%ymm14
	vpblendd	$192,%ymm12,%ymm3,%ymm3
	vpblendd	$192,%ymm13,%ymm15,%ymm15
	vpblendd	$192,%ymm13,%ymm5,%ymm5
	vpblendd	$192,%ymm11,%ymm14,%ymm14
	vpternlogq	$0xC6,%ymm15,%ymm10,%ymm3
	vpternlogq	$0xC6,%ymm14,%ymm12,%ymm5

	vpsrldq	$8,%ymm8,%ymm7
	vpandn	%ymm7,%ymm8,%ymm7

	vpblendd	$12,%ymm9,%ymm12,%ymm6
	vpblendd	$12,%ymm12,%ymm10,%ymm15
	vpblendd	$48,%ymm10,%ymm6,%ymm6
	vpblendd	$48,%ymm11,%ymm15,%ymm15
	vpblendd	$192,%ymm11,%ymm6,%ymm6
	vpblendd	$192,%ymm9,%ymm15,%ymm15
	vpternlogq	$0xC6,%ymm15,%ymm13,%ymm6

	vpermq	$30,%ymm8,%ymm4
	vpblendd	$48,%ymm0,%ymm4,%ymm15
	vpermq	$57,%ymm8,%ymm1
	vpblendd	$192,%ymm0,%ymm1,%ymm1

	vpblendd	$12,%ymm12,%ymm11,%ymm2
	vpblendd	$12,%ymm11,%ymm13,%ymm14
	vpblendd	$48,%ymm13,%ymm2,%ymm2
	vpblendd	$48,%ymm10,%ymm14,%ymm14
	vpblendd	$192,%ymm10,%ymm2,%ymm2
	vpblendd	$192,%ymm12,%ymm14,%ymm14
	vpternlogq	$0xC6,%ymm14,%ymm9,%ymm2

	vpermq	$0,%ymm7,%ymm7
	vpermq	$27,%ymm3,%ymm3
	vpermq	$141,%ymm5,%ymm5
	vpermq	$114,%ymm6,%ymm6

	vpblendd	$12,%ymm10,%ymm13,%ymm4
	vpblendd	$12,%ymm13,%ymm12,%ymm14
	vpblendd	$48,%ymm12,%ymm4,%ymm4
	vpblendd	$48,%ymm9,%ymm14,%ymm14
	vpblendd	$192,%ymm9,%ymm4,%ymm4
	vpblendd	$192,%ymm10,%ymm14,%ymm14

	vpternlogq	$0xC6,%ymm15,%ymm8,%ymm1
	vpternlogq	$0xC6,%ymm14,%ymm11,%ymm4


	vpternlogq	$0x96,(%r10),%ymm7,%ymm0
	leaq	32(%r10),%r10

	decl	%eax
	jnz	.Loop_avx512vl
