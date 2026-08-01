# Canonical encoder test inventory

> **Check mark means 100% done with no cheating. NO COMMENTARY OR STATUS. YOU MAY ONLY CHECK OFF BOXES**

## Immediate red-team

- [x] magnitude_all_significand_bits_affect_encoding
- [x] magnitude_encoding_is_injective_over_significand
- [x] finite_magnitude_cannot_equal_infinite_magnitude
- [x] negative_number_byte_order_matches_semantic_order
- [x] negative_infinity_sorts_below_every_finite_number
- [x] positive_infinity_sorts_above_every_finite_number
- [x] canonical_writer_output_is_always_readable
- [x] max_writer_nesting_never_exceeds_reader_capacity
- [ ] scan_rejection_matches_spec_rejection_except_depth_limit
- [x] accepted_scan_prefix_is_complete
- [x] refusal_position_is_suffix_of_original_input
- [x] inverted_interval_is_unconstructible
- [x] set_permutations_encode_identically
- [x] set_duplicates_encode_identically
- [x] vector_components_are_numeric_only
- [x] string_payload_is_valid_utf8
- [ ] json_payload_is_json_domain_only
- [x] validity_payload_cannot_be_arbitrary_bytes
- [x] geometry_payload_cannot_be_arbitrary_bytes

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

- [x] escape_empty_is_double_zero
- [x] escape_zero_is_zero_ff
- [x] escape_nonzero_bytes_are_unchanged
- [x] escape_multiple_zeroes_are_unambiguous
- [x] escape_body_never_contains_terminator
- [x] escape_body_never_ends_in_zero
- [x] escape_terminator_occurs_exactly_once_at_end
- [x] escape_is_injective_exhaustive
- [x] escape_preserves_order_exhaustive
- [x] escaped_encodings_are_prefix_free_exhaustive
- [x] escaped_prefix_payload_sorts_before_extension
- [x] escaped_ff_boundary_preserves_order
- [x] escaped_long_zero_runs_preserve_order
- [x] delim_scan_accepts_every_escape_output
- [x] delim_scan_stops_before_trailing_bytes
- [x] delim_scan_rejects_empty_input
- [x] delim_scan_rejects_single_zero
- [x] delim_scan_rejects_zero_followed_by_invalid_companion
- [x] delim_scan_reports_bad_escape_at_invalid_companion
- [x] delim_scan_reports_truncation_at_end
- [x] delim_scan_matches_delim_end_exhaustive
- [x] delim_scan_never_panics_on_arbitrary_bytes

## Rows

- [x] empty_row_is_struct_end
- [x] single_element_row_scans_exactly
- [x] multi_element_row_scans_exactly
- [x] row_scanner_stops_before_trailing_bytes
- [x] row_order_empty_before_nonempty
- [x] row_order_strict_prefix_before_extension
- [x] row_order_first_differing_element_decides
- [x] row_order_ignores_later_elements_after_difference
- [x] row_order_matches_encoded_byte_order
- [x] row_encodings_are_prefix_free
- [x] row_element_cannot_equal_terminator
- [x] row_element_cannot_sort_below_terminator
- [x] row_rejects_missing_terminator
- [x] row_rejects_truncated_element
- [x] row_rejects_unknown_element_tag
- [x] wide_row_is_stack_safe
- [x] deeply_nested_rows_respect_depth_policy
- [x] row_of_complete_values_is_complete
- [x] row_locality_survives_arbitrary_trailing_bytes

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

- [x] nesting_just_below_limit_is_accepted
- [x] nesting_at_limit_has_defined_behavior
- [x] nesting_just_above_limit_returns_too_deep
- [x] json_nesting_boundary_is_exact
- [x] list_nesting_boundary_is_exact
- [x] mixed_container_nesting_boundary_is_exact
- [x] wide_structure_does_not_consume_depth_budget
- [x] depth_limit_prevents_stack_overflow
- [x] writer_cannot_mint_value_reader_refuses
- [x] canonical_bytes_invariant_implies_executable_readability

## Construction authority and compile-fail

- [x] canonical_bytes_fields_are_inaccessible
- [x] canonical_bytes_cannot_be_forged_outside_module
- [x] body_type_is_inaccessible
- [x] body_fields_are_inaccessible
- [x] seal_function_is_inaccessible
- [x] raw_tag_cannot_be_supplied_by_external_caller
- [x] raw_body_bytes_cannot_be_supplied_by_external_caller
- [x] magnitude_fields_are_inaccessible
- [x] magnitude_cannot_be_built_from_raw_bytes
- [x] regex_flags_fields_are_inaccessible
- [x] regex_flags_cannot_contain_unknown_bits
- [x] repr_has_only_int_and_float_variants
- [x] nan_representation_byte_cannot_be_selected_by_caller
- [x] numeric_class_byte_cannot_be_selected_by_caller
- [x] interval_marker_byte_cannot_be_selected_by_caller
- [x] raw_set_sealer_is_not_public
- [x] raw_set_sealer_has_only_canonical_set_callers
- [x] public_api_does_not_expose_raw_grammar_authority

## Numeric encoding

- [x] numeric_classes_sort_negative_zero_positive_nan
- [x] zero_int_sorts_before_zero_float
- [x] equal_magnitude_int_sorts_before_float
- [x] tie_break_is_consulted_only_after_magnitude
- [x] magnitude_is_exactly_released_width
- [x] magnitude_exponent_is_big_endian
- [x] magnitude_fraction_is_big_endian
- [x] magnitude_all_input_bits_affect_output
- [x] magnitude_finite_constructor_is_injective
- [x] magnitude_infinite_constructor_is_unique
- [x] finite_domain_excludes_infinity_sentinel
- [x] positive_magnitude_order_matches_semantic_order
- [x] negative_magnitude_order_is_reversed_correctly
- [x] negative_exponent_boundary_orders_correctly
- [x] negative_fraction_boundary_orders_correctly
- [x] positive_exponent_boundary_orders_correctly
- [x] positive_fraction_boundary_orders_correctly
- [x] fraction_carry_transition_preserves_order
- [x] exponent_carry_transition_preserves_order
- [x] negative_infinity_is_global_numeric_minimum
- [x] positive_infinity_sorts_below_nan
- [x] nan_sorts_above_every_numeric_value
- [x] nan_has_exactly_one_encoding
- [x] numeric_encoding_is_injective_across_classes
- [x] numeric_semantic_equality_implies_identical_bytes
- [x] numeric_semantic_order_matches_bytes_property
- [x] numeric_total_order_matches_database_number_order
- [x] numeric_golden_vectors_cover_every_boundary

## Strings and byte strings

- [x] empty_string_encodes_canonically
- [x] empty_bytes_encodes_canonically
- [x] string_prefix_sorts_before_string_extension
- [x] bytes_prefix_sorts_before_bytes_extension
- [x] string_order_matches_semantic_string_order
- [x] bytes_order_matches_raw_byte_order
- [x] string_and_bytes_same_payload_have_distinct_encodings
- [x] string_rejects_invalid_utf8
- [x] string_embedded_zero_roundtrips
- [x] bytes_all_values_roundtrip
- [x] string_golden_vectors_cover_utf8_boundaries
- [x] bytes_golden_vectors_cover_zero_and_ff

## Regex

- [x] regex_all_eight_flag_combinations_are_unique
- [x] regex_unknown_flag_bits_are_unconstructible
- [x] regex_pattern_is_primary_sort_key
- [x] regex_flags_are_secondary_sort_key
- [x] regex_flag_bit_layout_matches_released_format
- [x] regex_empty_pattern_is_canonical
- [x] regex_pattern_rejects_invalid_utf8
- [x] regex_encoding_is_injective
- [x] regex_golden_vectors_cover_all_flags

## UUID

- [x] uuid_encoding_is_exactly_sixteen_bytes_after_tag
- [x] uuid_encoding_is_injective
- [x] uuid_order_matches_semantic_uuid_order
- [x] uuid_zero_and_ff_boundaries
- [x] uuid_golden_vectors_are_architecture_independent

## JSON

- [x] json_wraps_exactly_one_complete_value
- [x] json_encoding_order_matches_inner_value_order
- [x] json_encoding_is_injective
- [ ] json_rejects_non_json_database_values
- [x] json_nested_lists_roundtrip
- [ ] json_nested_objects_are_canonical
- [ ] json_object_key_permutations_encode_identically
- [ ] json_duplicate_object_keys_are_rejected_or_normalized
- [x] json_depth_boundary_matches_reader_policy
- [x] json_golden_vectors_cover_every_json_kind

## Vectors

- [x] vector_dimension_equals_component_count
- [x] vector_dimension_is_big_endian
- [x] vector_dimension_is_primary_sort_key
- [x] vector_components_are_secondary_sort_key
- [x] shorter_dimension_sorts_before_longer_dimension
- [x] same_dimension_uses_component_lexicographic_order
- [x] zero_dimension_vector_is_canonical
- [x] vector_rejects_non_numeric_components
- [x] vector_rejects_heterogeneous_components
- [x] vector_nan_component_order_is_defined
- [x] vector_encoding_is_injective
- [x] vector_component_count_overflow_is_unconstructible
- [x] vector_large_row_is_stack_safe
- [x] vector_golden_vectors_cover_dimension_boundaries

## Lists and sets

- [x] list_preserves_element_order
- [x] list_prefix_sorts_before_list_extension
- [x] list_first_differing_element_decides
- [x] list_encoding_is_injective
- [x] empty_list_and_empty_set_are_distinct
- [x] list_and_set_same_elements_are_distinct
- [x] set_input_is_sorted_before_sealing
- [x] set_input_is_deduplicated_before_sealing
- [x] set_permutation_invariance
- [x] set_duplicate_invariance
- [x] set_normalization_is_idempotent
- [x] set_encoding_is_injective_over_semantic_sets
- [x] set_order_matches_canonical_element_order
- [x] nested_list_set_values_remain_prefix_free
- [x] raw_set_sealer_cannot_bypass_normalization

## Intervals

- [x] empty_interval_sorts_before_every_inhabited_interval
- [x] empty_interval_has_exactly_one_encoding
- [x] unbounded_lower_sorts_before_every_bounded_lower
- [x] unbounded_upper_sorts_after_every_bounded_upper
- [x] lower_endpoint_is_primary_sort_key
- [x] upper_endpoint_is_secondary_sort_key
- [x] fully_unbounded_interval_is_canonical
- [x] point_interval_is_canonical
- [x] empty_interval_cannot_collide_with_inhabited_interval
- [x] lower_unbounded_marker_cannot_collide_with_timestamp
- [x] upper_unbounded_marker_cannot_collide_with_timestamp
- [x] interval_encoding_is_injective
- [x] interval_semantic_order_matches_byte_order
- [x] interval_golden_vectors_cover_all_bound_combinations

## Validity and geometry

- [x] validity_encoding_has_exactly_nine_payload_bytes
- [x] validity_invalid_states_are_unconstructible
- [x] validity_encoding_is_injective
- [x] validity_semantic_order_matches_byte_order
- [x] validity_golden_vectors_cover_temporal_boundaries
- [x] geometry_encoding_has_exactly_eight_payload_bytes
- [x] geometry_invalid_states_are_unconstructible
- [x] geometry_encoding_is_injective
- [x] geometry_semantic_order_matches_byte_order
- [x] geometry_golden_vectors_cover_spatial_boundaries

## Whole-domain canonical law

- [x] every_public_mint_produces_complete_encoding
- [x] every_public_mint_produces_executable_reading
- [x] every_pair_of_canonical_encodings_is_prefix_incomparable
- [x] every_semantically_equal_pair_has_identical_bytes
- [x] every_semantically_distinct_pair_has_distinct_bytes
- [x] every_semantic_order_pair_matches_lexicographic_bytes
- [x] cross_kind_order_matches_tag_order
- [x] whole_domain_order_is_reflexive
- [x] whole_domain_order_is_antisymmetric
- [x] whole_domain_order_is_transitive
- [x] whole_domain_order_is_total
- [x] whole_domain_encoding_is_injective
- [x] whole_domain_encoding_is_deterministic
- [x] nested_whole_domain_values_preserve_order
- [x] semantic_oracle_does_not_reuse_encoded_byte_comparison

## Fuzzing and differential

- [x] exhaustive_all_byte_strings_up_to_small_bound
- [x] exhaustive_all_small_semantic_values
- [x] property_random_nested_values_are_complete
- [x] property_random_nested_values_are_prefix_free
- [x] property_random_semantic_pairs_preserve_order
- [x] property_random_semantic_values_are_injective
- [x] fuzz_scan_value_never_panics
- [x] fuzz_shape_scan_never_panics
- [x] fuzz_delim_scan_never_panics
- [x] fuzz_mutated_valid_encodings_never_overread
- [x] fuzz_mutated_valid_encodings_never_have_two_readings
- [x] differential_encoder_matches_independent_reference
- [x] differential_scanner_matches_independent_reference
- [x] freeze_v1_candidate_golden_corpus
