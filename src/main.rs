// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use clap::Parser;
use log::info;
use oci_distribution::{secrets::RegistryAuth, Client, Reference};
use sha2::{Digest, Sha384};
use std::fs::File;
use std::io::Read;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    measurement: Vec<String>,
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

async fn image_hash(client: &mut Client, image_url: &str) -> Result<Vec<u8>> {
    let reference = Reference::try_from(image_url).unwrap();

    let (_image_manifest, image_digest, _image_config) = client
        .pull_manifest_and_config(&reference, &RegistryAuth::Anonymous)
        .await
        .map_err(|e| anyhow!("Failed to pull manifest: {}", e.to_string()))?;

    info!("image_digest: {:?}", image_digest);

    let mut hasher = Sha384::new();
    hasher.update(&image_digest);
    let hash = hasher.finalize().to_vec();

    info!("image_hash: {}", to_hex_string(&hash));

    Ok(hash)
}

fn file_hash(file_path: &str) -> Result<Vec<u8>> {
    let mut hasher = Sha384::new();
    let mut file = File::open(file_path).map_err(|e| anyhow!("Failed to open file: {}", e))?;
    let chunk_size: usize = 0x1000;
    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        let n = file
            .by_ref()
            .take(chunk_size as u64)
            .read_to_end(&mut chunk)
            .map_err(|e| anyhow!("Failed to read file: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
        if n < chunk_size {
            break;
        }
    }

    let hash = hasher.finalize().to_vec();

    info!("hash: {}", to_hex_string(&hash));

    Ok(hash)
}

fn string_hash(string: &str) -> Result<Vec<u8>> {
    let mut hasher = Sha384::new();
    hasher.update(string);
    let hash = hasher.finalize().to_vec();

    info!("hash: {}", to_hex_string(&hash));

    Ok(hash)
}

// Usage example:
// RUST_LOG=info cargo run -- image:hello-world \
//          string:sha384:`sha384sum -z xxx.bin | awk '{print $1}'` \
//          file:digest.txt
//
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("measurement: {:?}", args.measurement);

    let mut client = Client::default();
    let mut current_hash = vec![0u8; 48];
    for m in args.measurement {
        let (t, target) = m
            .split_once(':')
            .ok_or_else(|| anyhow!("Failed to get type and value in \"{}\"", m))?;

        info!("measurement target: {}", target);

        let hash =
            match t {
                "image" => image_hash(&mut client, target)
                    .await
                    .map_err(|e| anyhow!("Failed to hash \"{}\": {}", target, e))?,
                "string" => string_hash(target)
                    .map_err(|e| anyhow!("Failed to hash \"{}\": {}", target, e))?,
                "file" => file_hash(target)
                    .map_err(|e| anyhow!("Failed to hash \"{}\": {}", target, e))?,
                _ => {
                    return Err(anyhow!("Unexpected type \"{}\"", t));
                }
            };
        let mut hasher = Sha384::new();
        hasher.update(&current_hash);
        hasher.update(&hash);
        current_hash = hasher.finalize().to_vec();
    }

    println!("reference value: {}", to_hex_string(&current_hash));

    Ok(())
}
