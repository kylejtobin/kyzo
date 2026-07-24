// Presence fixture for condemned kind `verbatim`. A true syn::Item::Verbatim
// cannot be authored inside a file syn::parse_file accepts — by definition
// Verbatim is what syn could not interpret. Load checks file presence; the
// classify path for Verbatim is the live tree when syn yields Item::Verbatim.
