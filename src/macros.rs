macro_rules! impl_sha3 {
    ($name:ident, $output_size:ident, $rate:ident, $pad:expr, $alg_name:expr $(,)?) => {
        #[doc = concat!($alg_name, " hasher state.")]
        #[derive(Clone)]
        pub struct $name {
            #[doc(hidden)]
            state: Sha3State<{ <$rate>::USIZE }, $pad>,
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self { state: Default::default() }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.state.reset();
            }
        }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                unsafe { self.state.update(data.as_ptr(), data.len()) }
            }
        }

        impl FixedOutput for $name {
            #[inline]
            fn finalize_into(mut self, out: &mut Output<Self>) {
                unsafe { self.state.finalize(out.as_mut_ptr()) }
            }
        }

        impl FixedOutputReset for $name {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                unsafe { self.state.finalize(out.as_mut_ptr()) };
                Reset::reset(self);
            }
        }

        impl $name {
            /// Specialization of [`Digest::digest`] to avoid unnecessary intermediate stack copies.
            ///
            /// See: <https://github.com/rust-lang/rust/issues/146056>
            #[inline]
            pub fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
                Self::digest_inner(data.as_ref())
            }

            #[inline]
            fn digest_inner(data: &[u8]) -> Output<Self> {
                unsafe { crate::backend::digest::<Self, { <$rate>::USIZE }, $pad>(data) }
            }

            /// Number of messages that [`digest_batch`](Self::digest_batch) hashes in one
            /// permutation pass: 8 with AVX-512F, 4 with AVX2, 2 with NEON, and 1 otherwise.
            pub const BATCH_LANES: usize = crate::backend::batch::BATCH_LANES;

            /// Hashes each input and calls `f` with the input and its digest, in input order.
            ///
            /// This is equivalent to calling [`digest`](Self::digest) on each input, but hashes
            /// up to [`BATCH_LANES`](Self::BATCH_LANES) inputs at once, one per SIMD vector lane.
            /// Inputs may have any length. A group of inputs takes as many permutations as its
            /// longest input needs, so inputs of similar length make the best use of the lanes.
            #[inline]
            pub fn digest_batch<T: AsRef<[u8]>>(
                inputs: impl IntoIterator<Item = T>,
                f: impl FnMut(T, Output<Self>),
            ) {
                crate::backend::batch::digest_batch::<Self, { <$rate>::USIZE }, $pad, T>(inputs, f)
            }
        }
    };

    (
        $name:ident, $output_size:ident, $rate:ident, $pad:expr, $alg_name:expr, $oid:literal $(,)?
    ) => {
        impl_sha3!($name, $output_size, $rate, $pad, $alg_name);

        #[cfg(feature = "oid")]
        #[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
        impl AssociatedOid for $name {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        }
    };
}

/// Expands `$body` once for each index in the range, with `$i` bound to the index.
macro_rules! seq {
    ($i:ident in 0..8 => $body:block) => {
        seq!(@expand $i $body 0 1 2 3 4 5 6 7)
    };
    ($i:ident in 0..25 => $body:block) => {
        seq!(@expand $i $body 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24)
    };
    (@expand $i:ident $body:block $($n:literal)*) => {
        $({
            let $i: usize = $n;
            $body
        })*
    };
}
