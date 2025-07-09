// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use tari_features::resolver::build_features;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_features();
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path("proto/descriptor.bin")
        .compile_protos(
            &["proto/base_node.proto", "proto/wallet.proto", "proto/p2pool.proto"],
            &["proto"],
        )?;

    Ok(())
}
