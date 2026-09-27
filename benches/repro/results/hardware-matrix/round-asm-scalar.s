.Loop:
	movq	-100(%rdi),%r8
	movq	-52(%rdi),%r9
	movq	-4(%rdi),%r10
	movq	44(%rdi),%r11

	xorq	-84(%rdi),%rcx
	xorq	-76(%rdi),%rdx
	xorq	%r8,%rax
	xorq	-92(%rdi),%rbx
	xorq	-44(%rdi),%rcx
	xorq	-60(%rdi),%rax
	movq	%rbp,%r12
	xorq	-68(%rdi),%rbp

	xorq	%r10,%rcx
	xorq	-20(%rdi),%rax
	xorq	-36(%rdi),%rdx
	xorq	%r9,%rbx
	xorq	-28(%rdi),%rbp

	xorq	36(%rdi),%rcx
	xorq	20(%rdi),%rax
	xorq	4(%rdi),%rdx
	xorq	-12(%rdi),%rbx
	xorq	12(%rdi),%rbp

	movq	%rcx,%r13
	rolq	$1,%rcx
	xorq	%rax,%rcx
	xorq	%r11,%rdx

	rolq	$1,%rax
	xorq	%rdx,%rax
	xorq	28(%rdi),%rbx

	rolq	$1,%rdx
	xorq	%rbx,%rdx
	xorq	52(%rdi),%rbp

	rolq	$1,%rbx
	xorq	%rbp,%rbx

	rolq	$1,%rbp
	xorq	%r13,%rbp
	xorq	%rcx,%r9
	xorq	%rdx,%r10
	rolq	$44,%r9
	xorq	%rbp,%r11
	xorq	%rax,%r12
	rolq	$43,%r10
	xorq	%rbx,%r8
	movq	%r9,%r13
	rolq	$21,%r11
	orq	%r10,%r9
	xorq	%r8,%r9
	rolq	$14,%r12

	xorq	(%r15),%r9
	leaq	8(%r15),%r15

	movq	%r12,%r14
	andq	%r11,%r12
	movq	%r9,-100(%rsi)
	xorq	%r10,%r12
	notq	%r10
	movq	%r12,-84(%rsi)

	orq	%r11,%r10
	movq	76(%rdi),%r12
	xorq	%r13,%r10
	movq	%r10,-92(%rsi)

	andq	%r8,%r13
	movq	-28(%rdi),%r9
	xorq	%r14,%r13
	movq	-20(%rdi),%r10
	movq	%r13,-68(%rsi)

	orq	%r8,%r14
	movq	-76(%rdi),%r8
	xorq	%r11,%r14
	movq	28(%rdi),%r11
	movq	%r14,-76(%rsi)


	xorq	%rbp,%r8
	xorq	%rdx,%r12
	rolq	$28,%r8
	xorq	%rcx,%r11
	xorq	%rax,%r9
	rolq	$61,%r12
	rolq	$45,%r11
	xorq	%rbx,%r10
	rolq	$20,%r9
	movq	%r8,%r13
	orq	%r12,%r8
	rolq	$3,%r10

	xorq	%r11,%r8
	movq	%r8,-36(%rsi)

	movq	%r9,%r14
	andq	%r13,%r9
	movq	-92(%rdi),%r8
	xorq	%r12,%r9
	notq	%r12
	movq	%r9,-28(%rsi)

	orq	%r11,%r12
	movq	-44(%rdi),%r9
	xorq	%r10,%r12
	movq	%r12,-44(%rsi)

	andq	%r10,%r11
	movq	60(%rdi),%r12
	xorq	%r14,%r11
	movq	%r11,-52(%rsi)

	orq	%r10,%r14
	movq	4(%rdi),%r10
	xorq	%r13,%r14
	movq	52(%rdi),%r11
	movq	%r14,-60(%rsi)


	xorq	%rbp,%r10
	xorq	%rax,%r11
	rolq	$25,%r10
	xorq	%rdx,%r9
	rolq	$8,%r11
	xorq	%rbx,%r12
	rolq	$6,%r9
	xorq	%rcx,%r8
	rolq	$18,%r12
	movq	%r10,%r13
	andq	%r11,%r10
	rolq	$1,%r8

	notq	%r11
	xorq	%r9,%r10
	movq	%r10,-12(%rsi)

	movq	%r12,%r14
	andq	%r11,%r12
	movq	-12(%rdi),%r10
	xorq	%r13,%r12
	movq	%r12,-4(%rsi)

	orq	%r9,%r13
	movq	84(%rdi),%r12
	xorq	%r8,%r13
	movq	%r13,-20(%rsi)

	andq	%r8,%r9
	xorq	%r14,%r9
	movq	%r9,12(%rsi)

	orq	%r8,%r14
	movq	-60(%rdi),%r9
	xorq	%r11,%r14
	movq	36(%rdi),%r11
	movq	%r14,4(%rsi)


	movq	-68(%rdi),%r8

	xorq	%rcx,%r10
	xorq	%rdx,%r11
	rolq	$10,%r10
	xorq	%rbx,%r9
	rolq	$15,%r11
	xorq	%rbp,%r12
	rolq	$36,%r9
	xorq	%rax,%r8
	rolq	$56,%r12
	movq	%r10,%r13
	orq	%r11,%r10
	rolq	$27,%r8

	notq	%r11
	xorq	%r9,%r10
	movq	%r10,28(%rsi)

	movq	%r12,%r14
	orq	%r11,%r12
	xorq	%r13,%r12
	movq	%r12,36(%rsi)

	andq	%r9,%r13
	xorq	%r8,%r13
	movq	%r13,20(%rsi)

	orq	%r8,%r9
	xorq	%r14,%r9
	movq	%r9,52(%rsi)

	andq	%r14,%r8
	xorq	%r11,%r8
	movq	%r8,44(%rsi)


	xorq	-84(%rdi),%rdx
	xorq	-36(%rdi),%rbp
	rolq	$62,%rdx
	xorq	68(%rdi),%rcx
	rolq	$55,%rbp
	xorq	12(%rdi),%rax
	rolq	$2,%rcx
	xorq	20(%rdi),%rbx
	xchgq	%rsi,%rdi
	rolq	$39,%rax
	rolq	$41,%rbx
	movq	%rdx,%r13
	andq	%rbp,%rdx
	notq	%rbp
	xorq	%rcx,%rdx
	movq	%rdx,92(%rdi)

	movq	%rax,%r14
	andq	%rbp,%rax
	xorq	%r13,%rax
	movq	%rax,60(%rdi)

	orq	%rcx,%r13
	xorq	%rbx,%r13
	movq	%r13,84(%rdi)

	andq	%rbx,%rcx
	xorq	%r14,%rcx
	movq	%rcx,76(%rdi)

	orq	%r14,%rbx
	xorq	%rbp,%rbx
	movq	%rbx,68(%rdi)

	movq	%rdx,%rbp
	movq	%r13,%rdx

	testq	$255,%r15
	jnz	.Loop
