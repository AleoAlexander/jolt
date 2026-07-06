use crate::sequence_builder::{EdBlsDivQ, EdBlsMulQ, EdBlsSquareQ};

jolt_inlines_sdk::register_inlines! {
    trace_file: "edwards_bls12_trace.joltinline",
    extension: jolt_inlines_sdk::host::InlineExtension::EdwardsBls12,
    ops: [
        EdBlsMulQ,
        EdBlsSquareQ,
        EdBlsDivQ,
    ],
}
