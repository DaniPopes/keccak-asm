//! Assembly implementation of the [SHA-3] compression functions.
//!
//! This crate is not intended for direct use, most users should
//! prefer the [`sha3`] crate with enabled `asm` feature instead.
//!
//! Only x86, x86-64, and (partially) AArch64 architectures are
//! currently supported.
//!
//! [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
//! [`sha3`]: https://crates.io/crates/sha3

#![no_std]
#![warn(missing_docs, rust_2018_idioms)]

// TODO: Update this when adding support for new architectures
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("crate can only be used on x86, x86-64 and aarch64 architectures");

/// SHA-3 state buffer.
pub type Buffer = [u64; 25];

// Derived from OpenSSL:
// https://github.com/openssl/openssl/blob/60421893a286bb9eb7fb7c2454b84af9778ffca4/crypto/sha/keccak1600.c#L14-L17
#[link(name = "keccak", kind = "static")]
extern "C" {
    /// SHA-3 absorb, defined in assembly.
    ///
    /// `r` is the rate (block size) of the function in bytes.
    ///
    /// C signature:
    ///
    /// ```c
    /// size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
    ///                    size_t r);
    /// ```
    pub fn SHA3_absorb(a: *mut Buffer, inp: *const u8, len: usize, r: usize) -> usize;

    /// SHA-3 squeeze, defined in assembly.
    ///
    /// `r` is the rate (block size) of the function in bytes.
    ///
    /// C signature:
    ///
    /// ```c
    /// pub fn SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);
    /// ```
    pub fn SHA3_squeeze(a: *mut Buffer, out: *mut u8, len: usize, r: usize);

}

#[cfg(keccakp1600)]
#[link(name = "keccak", kind = "static")]
extern "C" {
    /** Function to initialize the state to the logical value 0^width.
     * @param  state   Pointer to the state to initialize.
     */
    pub fn KeccakP1600_Initialize(state: *mut Buffer);

    /** Function to add (in GF(2), using bitwise exclusive-or) data given as bytes into the state.
     * The bit positions that are affected by this function are
     * from @a offset*8 to @a offset*8 + @a length*8.
     * (The bit positions, the x,y,z coordinates and their link are defined in the "Keccak reference".)
     * @param  state   Pointer to the state.
     * @param  data    Pointer to the input data.
     * @param  offset  Offset in bytes within the state.
     * @param  length  Number of bytes.
     * @pre    0 ≤ @a offset < (width in bytes)
     * @pre    0 ≤ @a offset + @a length ≤ (width in bytes)
     */
    pub fn KeccakP1600_AddBytes(state: *mut Buffer, data: *const u8, offset: usize, length: usize);

    /** Function to overwrite data given as bytes into the state.
     * The bit positions that are affected by this function are
     * from @a offset*8 to @a offset*8 + @a length*8.
     * (The bit positions, the x,y,z coordinates and their link are defined in the "Keccak reference".)
     * @param  state   Pointer to the state.
     * @param  data    Pointer to the input data.
     * @param  offset  Offset in bytes within the state.
     * @param  length  Number of bytes.
     * @pre    0 ≤ @a offset < (width in bytes)
     * @pre    0 ≤ @a offset + @a length ≤ (width in bytes)
     */
    pub fn KeccakP1600_OverwriteBytes(
        state: *mut Buffer,
        data: *const u8,
        offset: usize,
        length: usize,
    );

    /** Function to overwrite bytes in the state with zeroes.
     * The bits to modify are restricted to start from the bit position 0 and
     * to span a whole number of bytes.
     * @param  state   Pointer to the state.
     * @param  byteCount   The number of bytes, i.e., the length of the data
     *                     divided by 8 bits.
     * @pre    0 ≤ @a byteCount ≤ (width in bytes)
     */
    pub fn KeccakP1600_OverwriteWithZeroes(state: *mut Buffer, byteCount: usize);

    /** Function to apply the permutation on the state.
     * @param  state   Pointer to the state.
     */
    pub fn KeccakP1600_Permute_12rounds(state: *mut Buffer);

    /** Function to apply the permutation on the state.
     * @param  state   Pointer to the state.
     */
    pub fn KeccakP1600_Permute_24rounds(state: *mut Buffer);

    /** Function to apply on the state the permutation with the given number of rounds
     * among the permutation family.
     * @param  state   Pointer to the state.
     */
    pub fn KeccakP1600_Permute_Nrounds(state: *mut Buffer, rounds: usize);

    /** Function to retrieve data from the state.
     * The bit positions that are retrieved by this function are
     * from @a offset*8 to @a offset*8 + @a length*8.
     * (The bit positions, the x,y,z coordinates and their link are defined in the "Keccak reference".)
     * @param  state   Pointer to the state.
     * @param  data    Pointer to the area where to store output data.
     * @param  offset  Offset in bytes within the state.
     * @param  length  Number of bytes.
     * @pre    0 ≤ @a offset < (width in bytes)
     * @pre    0 ≤ @a offset + @a length ≤ (width in bytes)
     */
    pub fn KeccakP1600_ExtractBytes(
        state: *const Buffer,
        data: *const u8,
        offset: usize,
        length: usize,
    );

    /** Function to retrieve data from the state,
     * to add  (in GF(2), using bitwise exclusive-or) them to the input buffer,
     * and to store the result in the output buffer.
     * The bit positions that are retrieved by this function are
     * from @a offset*8 to @a offset*8 + @a length*8.
     * (The bit positions, the x,y,z coordinates and their link are defined in the "Keccak reference".)
     * @param  state   Pointer to the state.
     * @param  input   Pointer to the input buffer.
     * @param  output  Pointer to the output buffer, which may be equal to @a input.
     * @param  offset  Offset in bytes within the state.
     * @param  length  Number of bytes.
     * @pre    0 ≤ @a offset < (width in bytes)
     * @pre    0 ≤ @a offset + @a length ≤ (width in bytes)
     */
    pub fn KeccakP1600_ExtractAndAddBytes(
        state: *const Buffer,
        input: *const u8,
        output: *mut u8,
        offset: usize,
        length: usize,
    );

    /** Function that has the same behavior as repeatedly calling
     *  - SnP_AddBytes() with a block of @a laneCount lanes from data;
     *  - SnP_Permute() on the state @a state;
     *  - and advancing @a data by @a laneCount lane sizes, until not enough data are available.
     * The function returns the number of bytes processed from @a data.
     * @param  state   Pointer to the state.
     * @param  laneCount   The number of lanes processed each time (i.e., the block size in lanes).
     * @param  data    Pointer to the data to use as input.
     * @param  dataByteLen The length of the input data in bytes.
     * @returns    The number of bytes processed.
     * @pre    0 < @a laneCount < SnP_laneCount
     */
    pub fn KeccakF1600_FastLoop_Absorb(
        state: *mut Buffer,
        laneCount: usize,
        data: *const u8,
        dataByteLen: usize,
    ) -> usize;
}

/// Safe wrapper for [`SHA3_absorb`]. See its docs for more.
#[inline(always)]
pub fn sha3_absorb(a: &mut Buffer, inp: &[u8], r: usize) -> usize {
    unsafe { SHA3_absorb(a, inp.as_ptr(), inp.len(), r) }
}

/// Safe wrapper for [`SHA3_squeeze`]. See its docs for more.
#[inline(always)]
pub fn sha3_squeeze(a: &mut Buffer, out: &mut [u8], r: usize) {
    unsafe { SHA3_squeeze(a, out.as_mut_ptr(), out.len(), r) }
}
