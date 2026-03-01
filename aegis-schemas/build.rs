// Protobuf code generation — schema definitions only, never wire encoding (D4)
// Generated types are used for documentation and type safety.
// Wire format is always canonical JSON (RFC 8785).

fn main() {
    // TODO: Enable when .proto files are added to schemas/
    // prost_build::compile_protos(&["../schemas/receipt.proto"], &["../schemas/"]).unwrap();
    println!("cargo:rerun-if-changed=../schemas/");
}
