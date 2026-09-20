//! Checks this connector's `declaration.ttl` against Contreforts' own
//! meta-shapes and lints - the same check `contreforts-core::declaration`
//! expects every connector's self-description to pass, exactly mirroring
//! `ds-sql-dps-rs/contreforts-connector/tests/declaration_validates.rs`.

const DECLARATION_TTL: &str = include_str!("../src/declaration.ttl");

#[test]
fn declaration_validates_against_contreforts_meta_shapes() {
    match contreforts_declaration::validate(DECLARATION_TTL) {
        Ok(_declaration) => {}
        Err(violations) => panic!("declaration.ttl failed validation:\n{violations}"),
    }
}
