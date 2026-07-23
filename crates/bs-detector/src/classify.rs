/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The default-deny classifier: every struct and enum in the boundary must
//! be an instance of a grammar construct; an item matching no construct is
//! a violation. The classifier only accepts — it never argues. Code
//! conforms to the grammar; the grammar never chases code.

use syn::visit::{self, Visit};

use crate::boundary::{SourceFile, span_line};
use crate::engines::Hit;
use crate::grammar::{ConstructKind, Grammar, StructuralRule};

/// Classify every struct and enum in `file`; return one hit per item that
/// matches no construct.
pub fn unclassified(grammar: &Grammar, file: &SourceFile) -> Vec<Hit> {
    struct V<'a> {
        rel: &'a str,
        grammar: &'a Grammar,
        hits: Vec<Hit>,
    }

    fn fields_all_private(fields: &syn::Fields) -> bool {
        fields
            .iter()
            .all(|f| matches!(f.vis, syn::Visibility::Inherited))
    }

    fn struct_matches(rule: StructuralRule, node: &syn::ItemStruct) -> bool {
        match rule {
            StructuralRule::TupleSinglePrivateField => matches!(
                &node.fields,
                syn::Fields::Unnamed(u) if u.unnamed.len() == 1
            ) && fields_all_private(&node.fields),
            StructuralRule::AllFieldsPrivate => fields_all_private(&node.fields),
            StructuralRule::NoStringVariantFields => false,
        }
    }

    fn enum_matches(rule: StructuralRule, node: &syn::ItemEnum) -> bool {
        match rule {
            StructuralRule::NoStringVariantFields => {
                use quote::ToTokens;
                node.variants.iter().all(|v| {
                    v.fields.iter().all(|f| {
                        let ty = f.ty.to_token_stream().to_string();
                        !ty.contains("String") && !ty.contains("str")
                    })
                })
            }
            StructuralRule::TupleSinglePrivateField | StructuralRule::AllFieldsPrivate => false,
        }
    }

    impl<'ast, 'a> Visit<'ast> for V<'a> {
        fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
            let classified = self
                .grammar
                .constructs
                .iter()
                .filter(|c| c.kind == ConstructKind::Struct)
                .any(|c| struct_matches(c.rule, node));
            if !classified {
                self.hits.push(Hit {
                    file: self.rel.to_string(),
                    line: span_line(&node.ident.span()),
                    construct: format!("unclassified-struct:{}", node.ident),
                });
            }
            visit::visit_item_struct(self, node);
        }
        fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
            let classified = self
                .grammar
                .constructs
                .iter()
                .filter(|c| c.kind == ConstructKind::Enum)
                .any(|c| enum_matches(c.rule, node));
            if !classified {
                self.hits.push(Hit {
                    file: self.rel.to_string(),
                    line: span_line(&node.ident.span()),
                    construct: format!("unclassified-enum:{}", node.ident),
                });
            }
            visit::visit_item_enum(self, node);
        }
    }

    let mut v = V {
        rel: &file.rel_path,
        grammar,
        hits: vec![],
    };
    v.visit_file(&file.ast);
    v.hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar::ConstructDef;

    fn test_grammar() -> Grammar {
        Grammar {
            bans_absolute: vec!["todo_bang".to_string()],
            bans: vec!["unwrap".to_string()],
            constructs: vec![
                ConstructDef {
                    name: "newtype-scalar".to_string(),
                    kind: ConstructKind::Struct,
                    rule: StructuralRule::TupleSinglePrivateField,
                },
                ConstructDef {
                    name: "sealed-struct".to_string(),
                    kind: ConstructKind::Struct,
                    rule: StructuralRule::AllFieldsPrivate,
                },
                ConstructDef {
                    name: "sum-type".to_string(),
                    kind: ConstructKind::Enum,
                    rule: StructuralRule::NoStringVariantFields,
                },
            ],
        }
    }

    fn parse(src: &str) -> SourceFile {
        SourceFile {
            rel_path: "crates/x/src/a.rs".to_string(),
            text: src.to_string(),
            ast: syn::parse_file(src).expect("fixture parses"),
        }
    }

    #[test]
    fn bite_unclassified_pub_field_struct_is_denied() {
        let f = parse("pub struct Open { pub name: u64 }");
        let hits = unclassified(&test_grammar(), &f);
        assert_eq!(hits.len(), 1, "a pub field matches no construct");
        assert_eq!(hits[0].construct, "unclassified-struct:Open");
    }

    #[test]
    fn bite_unclassified_string_enum_is_denied_and_clean_items_pass() {
        let f = parse(
            "struct Sealed { a: u64 }\nstruct Newtype(u64);\nenum Kind { A, B(u64) }\nenum Status { Named(String) }",
        );
        let hits = unclassified(&test_grammar(), &f);
        assert_eq!(hits.len(), 1, "only the String-carrying enum is denied");
        assert_eq!(hits[0].construct, "unclassified-enum:Status");
    }
}
