//! B2 weld (feature `field-accel-bind`): tie every advice-backed field op to
//! its 16-word record block `[x, y, z, w]` in the committed untrusted-advice
//! region.
//!
//! The guest passes its record blob as an `UntrustedAdvice<Vec<u8>>` input.
//! Postcard frames a `Vec<u8>` in the committed region as
//! `varint(len) ‖ bytes`, so the blob itself carries a deterministic head
//! pad: `pad = 128 − varint_size(len)`, making the first record block start
//! at **byte 128 = region word 16, always** — a 16-word boundary, so record
//! i's word j sits at region word `16·(i+1) + j` and the gadget's low-4-bit
//! word indexing is exact. The header row (varint + pad zeros) trivially
//! satisfies the gadget identity (y = z = w = 0). [`init`] recomputes the
//! pad rule from `len` alone and spoils on violation — the block base is
//! data-anchored, never a trusted offset. [`weld`] compares the 12 x/y/z
//! words of the current block against the operand/result words the op
//! actually used and spoils on mismatch (w is existential — never compared).
//! [`finalize`] spoils unless every block was welded, closing the
//! unwelded-tail attack. Block order = op execution order (single-threaded
//! guest).
//!
//! The blob slice the guest holds was deserialized from the untrusted-advice
//! region by generated guest code, so its bytes equal the committed region's
//! bytes through RAM checking; welding against the copy welds against the
//! commitment.
//!
//! Without the feature every call is a no-op (pass-1 collect builds and
//! measurement baselines). With the feature but before `init`, `weld` is a
//! no-op: the binding guarantee starts at `init`, which a bound guest calls
//! before its first field op (fixed in committed bytecode).

/// Bytes per record block: 4 values × 4 words × 8 bytes.
pub const RECORD_BYTES: usize = 128;

/// Postcard varint (LEB128) size of a `Vec` length prefix.
pub const fn varint_size(len: usize) -> usize {
    match len {
        0..0x80 => 1,
        0x80..0x4000 => 2,
        0x4000..0x20_0000 => 3,
        0x20_0000..0x1000_0000 => 4,
        _ => 5,
    }
}

/// Head pad enforced inside the blob so blocks start at region byte 128
/// (word 16 — a 16-word boundary; see module docs).
pub const fn head_pad(len: usize) -> usize {
    RECORD_BYTES - varint_size(len)
}

#[cfg(feature = "field-accel-bind")]
mod active {
    use super::{head_pad, RECORD_BYTES};

    // Guest execution is single-threaded; these statics are only ever
    // accessed sequentially.
    static mut BLOCKS: *const u8 = core::ptr::null();
    static mut LEN: usize = 0;
    static mut CURSOR: usize = 0;

    /// Register the record blob (the full deserialized `Vec<u8>`, pad
    /// included). Spoils unless `blob.len()` satisfies the pad rule.
    pub fn init(blob: &[u8]) {
        let pad = head_pad(blob.len());
        if blob.len() < pad || !(blob.len() - pad).is_multiple_of(RECORD_BYTES) {
            jolt_inlines_sdk::spoil_proof();
        }
        unsafe {
            BLOCKS = blob.as_ptr().add(pad);
            LEN = blob.len() - pad;
            CURSOR = 0;
        }
    }

    #[inline(always)]
    fn block_word(base: *const u8, word_idx: usize) -> u64 {
        let mut bytes = [0u8; 8];
        unsafe {
            core::ptr::copy_nonoverlapping(base.add(word_idx * 8), bytes.as_mut_ptr(), 8);
        }
        u64::from_le_bytes(bytes)
    }

    /// Compare (x, y, z) against the current block; advance the cursor.
    /// No-op before `init`.
    #[inline(always)]
    pub fn weld(x: &[u64; 4], y: &[u64; 4], z: &[u64; 4]) {
        let base = unsafe {
            if BLOCKS.is_null() {
                return;
            }
            if CURSOR + RECORD_BYTES > LEN {
                jolt_inlines_sdk::spoil_proof();
            }
            BLOCKS.add(CURSOR)
        };
        for i in 0..4 {
            if block_word(base, i) != x[i]
                || block_word(base, 4 + i) != y[i]
                || block_word(base, 8 + i) != z[i]
            {
                jolt_inlines_sdk::spoil_proof();
            }
        }
        unsafe {
            CURSOR += RECORD_BYTES;
        }
    }

    /// Spoil unless every block was welded (call at guest exit). No-op
    /// before `init`.
    pub fn finalize() {
        unsafe {
            if BLOCKS.is_null() {
                return;
            }
            if CURSOR != LEN {
                jolt_inlines_sdk::spoil_proof();
            }
        }
    }

    /// Number of blocks welded so far (guest-side sanity/debug).
    pub fn welded_count() -> usize {
        unsafe { CURSOR / RECORD_BYTES }
    }
}

#[cfg(feature = "field-accel-bind")]
pub use active::{finalize, init, weld, welded_count};

#[cfg(not(feature = "field-accel-bind"))]
mod inactive {
    /// No-op without `field-accel-bind`.
    #[inline(always)]
    pub fn init(_blob: &[u8]) {}

    /// No-op without `field-accel-bind`.
    #[inline(always)]
    pub fn weld(_x: &[u64; 4], _y: &[u64; 4], _z: &[u64; 4]) {}

    /// No-op without `field-accel-bind`.
    #[inline(always)]
    pub fn finalize() {}

    /// Always zero without `field-accel-bind`.
    #[inline(always)]
    pub fn welded_count() -> usize {
        0
    }
}

#[cfg(not(feature = "field-accel-bind"))]
pub use inactive::{finalize, init, weld, welded_count};
