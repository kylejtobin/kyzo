# Canonical encoder test inventory

> **Check mark means 100% done with no cheating. NO COMMENTARY OR STATUS. YOU MAY ONLY CHECK OFF BOXES**

## Immediate red-team

- [x] magnitude_all_significand_bits_affect_encoding
- [x] magnitude_encoding_is_injective_over_significand
- [x] finite_magnitude_cannot_equal_infinite_magnitude
- [x] negative_number_byte_order_matches_semantic_order
- [x] negative_infinity_sorts_below_every_finite_number
- [x] positive_infinity_sorts_above_every_finite_number
- [ ] canonical_writer_output_is_always_readable
- [ ] max_writer_nesting_never_exceeds_reader_capacity
- [ ] scan_rejection_matches_spec_rejection_except_depth_limit
- [x] accepted_scan_prefix_is_complete
- [x] refusal_position_is_suffix_of_original_input
- [x] inverted_interval_is_unconstructible
- [x] set_permutations_encode_identically
- [x] set_duplicates_encode_identically
- [x] vector_components_are_numeric_only
- [x] string_payload_is_valid_utf8
- [ ] json_payload_is_json_domain_only
- [ ] validity_payload_cannot_be_arbitrary_bytes
- [ ] geometry_payload_cannot_be_arbitrary_bytes

## Independent byte-order oracle

- [x] lex_le_matches_independent_slice_comparator_exhaustive
- [x] lex_le_reflexive_exhaustive
- [x] lex_le_antisymmetric_exhaustive
- [x] lex_le_transitive_exhaustive
- [x] lex_le_total_exhaustive
- [x] lex_le_empty_is_minimum
- [x] lex_le_strict_prefix_sorts_first
- [x] lex_le_first_differing_byte_decides
- [x] lex_le_long_common_prefix
- [x] lex_le_zero_and_ff_boundaries
- [x] is_prefix_matches_independent_starts_with
- [x] incomparable_rejects_every_strict_prefix_pair

## Concatenation and closure law

- [ ] concat_order_matches_lexicographic_product_order
- [ ] concat_order_equal_heads_defers_to_tail
- [ ] concat_order_distinct_heads_ignores_tail
- [ ] concat_order_handles_empty_heads
- [ ] concat_order_requires_prefix_incomparability
- [ ] concat_order_counterexample_collides_as_documented
- [ ] prefix_split_recovers_equal_heads
- [ ] prefix_split_recovers_tail_prefix
- [ ] complete_heads_discharge_concat_hypothesis
- [ ] nested_products_preserve_lexicographic_order

## Escaped byte strings

- [ ] escape_empty_is_double_zero
- [ ] escape_zero_is_zero_ff
- [ ] escape_nonzero_bytes_are_unchanged
- [ ] escape_multiple_zeroes_are_unambiguous
- [ ] escape_body_never_contains_terminator
- [ ] escape_body_never_ends_in_zero
- [ ] escape_terminator_occurs_exactly_once_at_end
- [ ] escape_is_injective_exhaustive
- [ ] escape_preserves_order_exhaustive
- [ ] escaped_encodings_are_prefix_free_exhaustive
- [ ] escaped_prefix_payload_sorts_before_extension
- [ ] escaped_ff_boundary_preserves_order
- [ ] escaped_long_zero_runs_preserve_order
- [ ] delim_scan_accepts_every_escape_output
- [ ] delim_scan_stops_before_trailing_bytes
- [ ] delim_scan_rejects_empty_input
- [ ] delim_scan_rejects_single_zero
- [ ] delim_scan_rejects_zero_followed_by_invalid_companion
- [ ] delim_scan_reports_bad_escape_at_invalid_companion
- [ ] delim_scan_reports_truncation_at_end
- [ ] delim_scan_matches_delim_end_exhaustive
- [ ] delim_scan_never_panics_on_arbitrary_bytes

## Rows

- [ ] empty_row_is_struct_end
- [ ] single_element_row_scans_exactly
- [ ] multi_element_row_scans_exactly
- [ ] row_scanner_stops_before_trailing_bytes
- [ ] row_order_empty_before_nonempty
- [ ] row_order_strict_prefix_before_extension
- [ ] row_order_first_differing_element_decides
- [ ] row_order_ignores_later_elements_after_difference
- [ ] row_order_matches_encoded_byte_order
- [ ] row_encodings_are_prefix_free
- [ ] row_element_cannot_equal_terminator
- [ ] row_element_cannot_sort_below_terminator
- [ ] row_rejects_missing_terminator
- [ ] row_rejects_truncated_element
- [ ] row_rejects_unknown_element_tag
- [ ] wide_row_is_stack_safe
- [ ] deeply_nested_rows_respect_depth_policy
- [ ] row_of_complete_values_is_complete
- [ ] row_locality_survives_arbitrary_trailing_bytes

## Grammar integrity

- [ ] grammar_exec_equals_grammar_spec
- [ ] grammar_is_well_formed
- [ ] grammar_has_no_duplicate_top_level_tags
- [ ] grammar_has_no_duplicate_nested_branch_keys
- [ ] grammar_has_no_unreachable_branches
- [ ] all_top_level_tags_sort_above_struct_end
- [ ] all_row_element_shapes_are_lead_marked
- [ ] all_row_element_shapes_consume_at_least_one_byte
- [ ] every_released_tag_has_expected_shape
- [ ] every_numeric_class_has_expected_shape
- [ ] every_interval_branch_has_expected_shape
- [ ] lower_bound_markers_have_expected_order
- [ ] upper_bound_markers_have_expected_order
- [ ] all_fixed_widths_match_released_format
- [ ] grammar_tag_table_matches_golden_snapshot
- [ ] grammar_branch_tables_match_golden_snapshot
- [ ] unknown_top_level_tag_is_rejected
- [ ] unknown_numeric_class_is_rejected
- [ ] unknown_interval_class_is_rejected
- [ ] changing_any_tag_breaks_format_snapshot
- [ ] changing_any_width_breaks_format_snapshot
- [ ] changing_any_branch_order_breaks_format_snapshot

## Shape algebra

- [ ] fixed_shape_accepts_exact_width
- [ ] fixed_shape_accepts_prefix_of_larger_buffer
- [ ] fixed_shape_rejects_short_buffer
- [ ] delimited_shape_matches_delim_spec
- [ ] product_shape_ends_after_both_factors
- [ ] product_shape_rejects_when_first_factor_rejects
- [ ] product_shape_rejects_when_second_factor_rejects
- [ ] sum_shape_selects_exact_matching_branch
- [ ] sum_shape_rejects_unknown_lead
- [ ] tagged_shape_uses_canonical_grammar
- [ ] row_shape_terminates_only_on_struct_end
- [ ] shape_end_is_bounded_for_all_shapes
- [ ] shape_end_is_local_for_all_shapes
- [ ] shape_end_is_total_for_arbitrary_bytes
- [ ] shape_scan_success_matches_shape_end
- [ ] shape_scan_non_depth_failure_matches_shape_end_none
- [ ] shape_scan_never_returns_zero_for_row_element
- [ ] malformed_custom_shape_cannot_cause_infinite_loop
- [ ] arbitrary_shape_and_input_never_panics

## Scanner and executable/spec equivalence

- [ ] scan_value_success_matches_scan_spec
- [ ] scan_value_rejection_matches_scan_spec_or_depth_limit
- [ ] scan_value_success_length_is_nonzero
- [ ] scan_value_success_length_is_within_input
- [ ] scan_value_success_prefix_is_complete
- [ ] scan_value_accepts_every_sealed_value
- [ ] scan_value_accepts_concatenated_values_one_at_a_time
- [ ] scan_value_preserves_exact_trailing_suffix
- [ ] scan_value_is_deterministic
- [ ] scan_value_never_panics_on_arbitrary_bytes
- [ ] scan_value_matches_independent_reference_parser
- [ ] every_truncated_prefix_of_valid_encoding_is_rejected
- [ ] every_one_byte_mutation_rejects_or_decodes_unambiguously
- [ ] every_accepted_mutation_has_exactly_one_reading
- [ ] complete_encoding_never_has_complete_strict_prefix
- [ ] complete_encoding_never_has_two_parse_boundaries

## Refusal correctness

- [ ] truncated_fixed_body_reports_eof_suffix
- [ ] truncated_delimited_body_reports_eof_suffix
- [ ] truncated_product_first_factor_reports_exact_suffix
- [ ] truncated_product_second_factor_reports_exact_suffix
- [ ] truncated_row_reports_exact_suffix
- [ ] truncated_nested_value_reports_exact_suffix
- [ ] unknown_tag_reports_original_unconsumed_suffix
- [ ] unknown_nested_branch_reports_exact_nested_suffix
- [ ] bad_escape_reports_suffix_beginning_at_bad_companion
- [ ] too_deep_reports_first_unread_nested_suffix
- [ ] refusal_reason_matches_actual_failure
- [ ] refusal_suffix_is_borrowed_from_original_input
- [ ] refusal_suffix_is_never_fabricated
- [ ] refusal_suffix_never_points_past_end
- [ ] refusal_location_composition_never_overflows
- [ ] non_too_deep_failure_implies_spec_rejection

## Depth and writer-reader closure

- [ ] nesting_just_below_limit_is_accepted
- [ ] nesting_at_limit_has_defined_behavior
- [ ] nesting_just_above_limit_returns_too_deep
- [ ] json_nesting_boundary_is_exact
- [ ] list_nesting_boundary_is_exact
- [ ] mixed_container_nesting_boundary_is_exact
- [ ] wide_structure_does_not_consume_depth_budget
- [ ] depth_limit_prevents_stack_overflow
- [ ] writer_cannot_mint_value_reader_refuses
- [ ] canonical_bytes_invariant_implies_executable_readability

## Construction authority and compile-fail

- [ ] canonical_bytes_fields_are_inaccessible
- [ ] canonical_bytes_cannot_be_forged_outside_module
- [ ] body_type_is_inaccessible
- [ ] body_fields_are_inaccessible
- [ ] seal_function_is_inaccessible
- [ ] raw_tag_cannot_be_supplied_by_external_caller
- [ ] raw_body_bytes_cannot_be_supplied_by_external_caller
- [ ] magnitude_fields_are_inaccessible
- [ ] magnitude_cannot_be_built_from_raw_bytes
- [ ] regex_flags_fields_are_inaccessible
- [ ] regex_flags_cannot_contain_unknown_bits
- [ ] repr_has_only_int_and_float_variants
- [ ] nan_representation_byte_cannot_be_selected_by_caller
- [ ] numeric_class_byte_cannot_be_selected_by_caller
- [ ] interval_marker_byte_cannot_be_selected_by_caller
- [ ] raw_set_sealer_is_not_public
- [ ] raw_set_sealer_has_only_canonical_set_callers
- [ ] public_api_does_not_expose_raw_grammar_authority

## Numeric encoding

- [ ] numeric_classes_sort_negative_zero_positive_nan
- [ ] zero_int_sorts_before_zero_float
- [ ] equal_magnitude_int_sorts_before_float
- [ ] tie_break_is_consulted_only_after_magnitude
- [ ] magnitude_is_exactly_released_width
- [ ] magnitude_exponent_is_big_endian
- [ ] magnitude_fraction_is_big_endian
- [ ] magnitude_all_input_bits_affect_output
- [ ] magnitude_finite_constructor_is_injective
- [ ] magnitude_infinite_constructor_is_unique
- [ ] finite_domain_excludes_infinity_sentinel
- [ ] positive_magnitude_order_matches_semantic_order
- [ ] negative_magnitude_order_is_reversed_correctly
- [ ] negative_exponent_boundary_orders_correctly
- [ ] negative_fraction_boundary_orders_correctly
- [ ] positive_exponent_boundary_orders_correctly
- [ ] positive_fraction_boundary_orders_correctly
- [ ] fraction_carry_transition_preserves_order
- [ ] exponent_carry_transition_preserves_order
- [ ] negative_infinity_is_global_numeric_minimum
- [ ] positive_infinity_sorts_below_nan
- [ ] nan_sorts_above_every_numeric_value
- [ ] nan_has_exactly_one_encoding
- [ ] numeric_encoding_is_injective_across_classes
- [ ] numeric_semantic_equality_implies_identical_bytes
- [ ] numeric_semantic_order_matches_bytes_property
- [ ] numeric_total_order_matches_database_number_order
- [ ] numeric_golden_vectors_cover_every_boundary

## Strings and byte strings

- [ ] empty_string_encodes_canonically
- [ ] empty_bytes_encodes_canonically
- [ ] string_prefix_sorts_before_string_extension
- [ ] bytes_prefix_sorts_before_bytes_extension
- [ ] string_order_matches_semantic_string_order
- [ ] bytes_order_matches_raw_byte_order
- [ ] string_and_bytes_same_payload_have_distinct_encodings
- [ ] string_rejects_invalid_utf8
- [ ] string_embedded_zero_roundtrips
- [ ] bytes_all_values_roundtrip
- [ ] string_golden_vectors_cover_utf8_boundaries
- [ ] bytes_golden_vectors_cover_zero_and_ff

## Regex

- [ ] regex_all_eight_flag_combinations_are_unique
- [ ] regex_unknown_flag_bits_are_unconstructible
- [ ] regex_pattern_is_primary_sort_key
- [ ] regex_flags_are_secondary_sort_key
- [ ] regex_flag_bit_layout_matches_released_format
- [ ] regex_empty_pattern_is_canonical
- [ ] regex_pattern_rejects_invalid_utf8
- [ ] regex_encoding_is_injective
- [ ] regex_golden_vectors_cover_all_flags

## UUID

- [ ] uuid_encoding_is_exactly_sixteen_bytes_after_tag
- [ ] uuid_encoding_is_injective
- [ ] uuid_order_matches_semantic_uuid_order
- [ ] uuid_zero_and_ff_boundaries
- [ ] uuid_golden_vectors_are_architecture_independent

## JSON

- [ ] json_wraps_exactly_one_complete_value
- [ ] json_encoding_order_matches_inner_value_order
- [ ] json_encoding_is_injective
- [ ] json_rejects_non_json_database_values
- [ ] json_nested_lists_roundtrip
- [ ] json_nested_objects_are_canonical
- [ ] json_object_key_permutations_encode_identically
- [ ] json_duplicate_object_keys_are_rejected_or_normalized
- [ ] json_depth_boundary_matches_reader_policy
- [ ] json_golden_vectors_cover_every_json_kind

## Vectors

- [ ] vector_dimension_equals_component_count
- [ ] vector_dimension_is_big_endian
- [ ] vector_dimension_is_primary_sort_key
- [ ] vector_components_are_secondary_sort_key
- [ ] shorter_dimension_sorts_before_longer_dimension
- [ ] same_dimension_uses_component_lexicographic_order
- [ ] zero_dimension_vector_is_canonical
- [ ] vector_rejects_non_numeric_components
- [ ] vector_rejects_heterogeneous_components
- [ ] vector_nan_component_order_is_defined
- [ ] vector_encoding_is_injective
- [ ] vector_component_count_overflow_is_unconstructible
- [ ] vector_large_row_is_stack_safe
- [ ] vector_golden_vectors_cover_dimension_boundaries

## Lists and sets

- [ ] list_preserves_element_order
- [ ] list_prefix_sorts_before_list_extension
- [ ] list_first_differing_element_decides
- [ ] list_encoding_is_injective
- [ ] empty_list_and_empty_set_are_distinct
- [ ] list_and_set_same_elements_are_distinct
- [ ] set_input_is_sorted_before_sealing
- [ ] set_input_is_deduplicated_before_sealing
- [ ] set_permutation_invariance
- [ ] set_duplicate_invariance
- [ ] set_normalization_is_idempotent
- [ ] set_encoding_is_injective_over_semantic_sets
- [ ] set_order_matches_canonical_element_order
- [ ] nested_list_set_values_remain_prefix_free
- [ ] raw_set_sealer_cannot_bypass_normalization

## Intervals

- [ ] empty_interval_sorts_before_every_inhabited_interval
- [ ] empty_interval_has_exactly_one_encoding
- [ ] unbounded_lower_sorts_before_every_bounded_lower
- [ ] unbounded_upper_sorts_after_every_bounded_upper
- [ ] lower_endpoint_is_primary_sort_key
- [ ] upper_endpoint_is_secondary_sort_key
- [ ] fully_unbounded_interval_is_canonical
- [ ] point_interval_is_canonical
- [ ] empty_interval_cannot_collide_with_inhabited_interval
- [ ] lower_unbounded_marker_cannot_collide_with_timestamp
- [ ] upper_unbounded_marker_cannot_collide_with_timestamp
- [ ] interval_encoding_is_injective
- [ ] interval_semantic_order_matches_byte_order
- [ ] interval_golden_vectors_cover_all_bound_combinations

## Validity and geometry

- [ ] validity_encoding_has_exactly_nine_payload_bytes
- [ ] validity_invalid_states_are_unconstructible
- [ ] validity_encoding_is_injective
- [ ] validity_semantic_order_matches_byte_order
- [ ] validity_golden_vectors_cover_temporal_boundaries
- [ ] geometry_encoding_has_exactly_eight_payload_bytes
- [ ] geometry_invalid_states_are_unconstructible
- [ ] geometry_encoding_is_injective
- [ ] geometry_semantic_order_matches_byte_order
- [ ] geometry_golden_vectors_cover_spatial_boundaries

## Whole-domain canonical law

- [ ] every_public_mint_produces_complete_encoding
- [ ] every_public_mint_produces_executable_reading
- [ ] every_pair_of_canonical_encodings_is_prefix_incomparable
- [ ] every_semantically_equal_pair_has_identical_bytes
- [ ] every_semantically_distinct_pair_has_distinct_bytes
- [ ] every_semantic_order_pair_matches_lexicographic_bytes
- [ ] cross_kind_order_matches_tag_order
- [ ] whole_domain_order_is_reflexive
- [ ] whole_domain_order_is_antisymmetric
- [ ] whole_domain_order_is_transitive
- [ ] whole_domain_order_is_total
- [ ] whole_domain_encoding_is_injective
- [ ] whole_domain_encoding_is_deterministic
- [ ] nested_whole_domain_values_preserve_order
- [ ] semantic_oracle_does_not_reuse_encoded_byte_comparison

## Fuzzing and differential

- [ ] exhaustive_all_byte_strings_up_to_small_bound
- [ ] exhaustive_all_small_semantic_values
- [ ] property_random_nested_values_are_complete
- [ ] property_random_nested_values_are_prefix_free
- [ ] property_random_semantic_pairs_preserve_order
- [ ] property_random_semantic_values_are_injective
- [ ] fuzz_scan_value_never_panics
- [ ] fuzz_shape_scan_never_panics
- [ ] fuzz_delim_scan_never_panics
- [ ] fuzz_mutated_valid_encodings_never_overread
- [ ] fuzz_mutated_valid_encodings_never_have_two_readings
- [ ] differential_encoder_matches_independent_reference
- [ ] differential_scanner_matches_independent_reference
- [ ] freeze_v1_candidate_golden_corpus
