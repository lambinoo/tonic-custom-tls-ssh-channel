fn main() {
    tonic_prost_build::compile_protos("service.proto").expect("Failed to build proto");
}
