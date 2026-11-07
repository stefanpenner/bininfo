/*
---
why: This file reads one OCI image layout stored in a tar archive.
uses: bininfo
how: bininfo calls this file when the tar has an oci-layout member.
This file reads index.json and the config blob.
This file does not unpack a layer.
---
*/

//! One OCI image layout in a tar archive.
//! `oci-layout` and `index.json` name the image.
//! This module does not unpack a layer.

pub mod page;

mod json;

use super::tar;
use json::Val;

const MANIFEST_CAP: usize = 32;
const LAYER_CAP: usize = 64;
const LIST_CAP: usize = 16;
const TEXT_CAP: usize = 256;

/// One manifest descriptor from `index.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub media_type: Option<String>,
    pub digest: Option<String>,
    pub size: Option<u64>,
    pub platform: Option<String>,
}

/// One image layer. `offset` is the tar body of the blob when the blob is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    pub media_type: Option<String>,
    pub digest: Option<String>,
    pub size: Option<u64>,
    pub offset: Option<u64>,
    pub stored: Option<u64>,
}

/// One tar member that is not the layout, the index, or a listed blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SideFile {
    pub name: String,
    pub offset: u64,
    pub stored: u64,
}

/// Facts from `oci-layout`, `index.json`, the manifest, and the config blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub layout: String,
    pub schema: Option<u64>,
    pub media_type: Option<String>,
    pub architecture: Option<String>,
    pub os: Option<String>,
    pub workdir: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub manifests: Vec<Descriptor>,
    pub layers: Vec<Layer>,
    pub files: Vec<SideFile>,
    pub more: bool,
}

/// True when the tar has an `oci-layout` member and that member names a layout version.
pub fn is_oci(bytes: &[u8]) -> bool {
    if !tar::is_tar(bytes) {
        return false;
    }
    let Ok(archive) = tar::parse(bytes) else {
        return false;
    };
    archive.members.iter().any(|member| {
        is_name(&member.name, "oci-layout")
            && tar::body(bytes, member).is_some_and(|body| {
                let token = b"imageLayoutVersion";
                body.windows(token.len()).any(|window| window == token)
            })
    })
}

/// Read the layout, the index, and the first manifest blob.
pub fn parse(bytes: &[u8]) -> Result<Image, String> {
    if !is_oci(bytes) {
        return Err("not an oci image".into());
    }
    let archive = tar::parse(bytes)?;
    let layout_member = find(&archive, "oci-layout").ok_or("oci layout is missing")?;
    let layout_body = tar::body(bytes, layout_member).ok_or("oci layout is missing")?;
    let layout_doc = json::parse(layout_body)?;
    let layout = json::get(&layout_doc.value, "imageLayoutVersion")
        .and_then(json::as_str)
        .ok_or("oci layout version is missing")?
        .to_string();
    let mut more = layout_doc.truncated;

    let index_member = find(&archive, "index.json").ok_or("oci index is missing")?;
    let index_body = tar::body(bytes, index_member).ok_or("oci index is missing")?;
    let index_doc = json::parse(index_body)?;
    more |= index_doc.truncated;
    let schema = json::get(&index_doc.value, "schemaVersion").and_then(json::as_u64);
    let media_type = owned_str(json::get(&index_doc.value, "mediaType"));

    let mut manifests = Vec::new();
    let mut manifest_val = None;
    if let Some(rows) = json::get(&index_doc.value, "manifests").and_then(json::as_arr) {
        if rows.len() > MANIFEST_CAP {
            more = true;
        }
        for row in rows.iter().take(MANIFEST_CAP) {
            manifests.push(descriptor(row));
        }
        if let Some(digest) = manifests.first().and_then(|row| row.digest.as_deref()) {
            if let Some(body) = blob_body(bytes, &archive, digest) {
                let doc = json::parse(body)?;
                more |= doc.truncated;
                manifest_val = Some(doc.value);
            }
        }
    } else if json::get(&index_doc.value, "layers").is_some() {
        manifest_val = Some(index_doc.value);
    }

    let mut architecture = None;
    let mut os = None;
    let mut workdir = None;
    let mut entrypoint = Vec::new();
    let mut cmd = Vec::new();
    let mut env = Vec::new();
    let mut layers = Vec::new();
    if let Some(manifest) = manifest_val.as_ref() {
        if manifests.is_empty() {
            manifests.push(descriptor(manifest));
        }
        if let Some(config) = json::get(manifest, "config") {
            if let Some(digest) = json::get(config, "digest").and_then(json::as_str) {
                if let Some(body) = blob_body(bytes, &archive, digest) {
                    let doc = json::parse(body)?;
                    more |= doc.truncated;
                    architecture = owned_str(json::get(&doc.value, "architecture"));
                    os = owned_str(json::get(&doc.value, "os"));
                    if let Some(cfg) = json::get(&doc.value, "config") {
                        workdir = owned_str(json::get(cfg, "WorkingDir"));
                        entrypoint = string_list(json::get(cfg, "Entrypoint"), &mut more);
                        cmd = string_list(json::get(cfg, "Cmd"), &mut more);
                        env = string_list(json::get(cfg, "Env"), &mut more);
                    }
                }
            }
        }
        if let Some(rows) = json::get(manifest, "layers").and_then(json::as_arr) {
            if rows.len() > LAYER_CAP {
                more = true;
            }
            for row in rows.iter().take(LAYER_CAP) {
                layers.push(layer(bytes, &archive, row));
            }
        }
    }

    let files = side_files(&archive, &layers);
    Ok(Image {
        layout,
        schema,
        media_type,
        architecture,
        os,
        workdir,
        entrypoint,
        cmd,
        env,
        manifests,
        layers,
        files,
        more,
    })
}

fn side_files(archive: &tar::Archive, layers: &[Layer]) -> Vec<SideFile> {
    let mut files = Vec::new();
    for member in &archive.members {
        if member.kind != "file" {
            continue;
        }
        if is_name(&member.name, "oci-layout") || is_name(&member.name, "index.json") {
            continue;
        }
        if layers
            .iter()
            .any(|layer| layer.offset == Some(member.offset))
        {
            continue;
        }
        if blob_digest(&member.name).is_some() {
            continue;
        }
        files.push(SideFile {
            name: clip(&member.name),
            offset: member.offset,
            stored: member.size,
        });
        if files.len() == LAYER_CAP {
            break;
        }
    }
    files
}

fn layer(bytes: &[u8], archive: &tar::Archive, row: &Val) -> Layer {
    let digest = owned_str(json::get(row, "digest"));
    let (offset, stored) = digest
        .as_deref()
        .and_then(|digest| find_blob(archive, digest))
        .map(|member| (Some(member.offset), Some(member.size)))
        .unwrap_or((None, None));
    let _ = bytes;
    Layer {
        media_type: owned_str(json::get(row, "mediaType")),
        digest,
        size: json::get(row, "size").and_then(json::as_u64),
        offset,
        stored,
    }
}

fn descriptor(row: &Val) -> Descriptor {
    let architecture = json::get(row, "platform")
        .and_then(|platform| json::get(platform, "architecture"))
        .and_then(json::as_str);
    let os = json::get(row, "platform")
        .and_then(|platform| json::get(platform, "os"))
        .and_then(json::as_str);
    let platform = match (os, architecture) {
        (Some(os), Some(architecture)) => Some(format!("{os}/{architecture}")),
        (Some(os), None) => Some(os.to_string()),
        (None, Some(architecture)) => Some(architecture.to_string()),
        (None, None) => None,
    };
    Descriptor {
        media_type: owned_str(json::get(row, "mediaType")),
        digest: owned_str(json::get(row, "digest")),
        size: json::get(row, "size").and_then(json::as_u64),
        platform,
    }
}

fn string_list(val: Option<&Val>, more: &mut bool) -> Vec<String> {
    let Some(rows) = val.and_then(json::as_arr) else {
        return Vec::new();
    };
    if rows.len() > LIST_CAP {
        *more = true;
    }
    rows.iter()
        .take(LIST_CAP)
        .filter_map(json::as_str)
        .map(clip)
        .collect()
}

fn owned_str(val: Option<&Val>) -> Option<String> {
    json::as_str(val?).map(clip)
}

fn clip(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars().take(TEXT_CAP) {
        out.push(ch);
    }
    out
}

fn blob_body<'a>(bytes: &'a [u8], archive: &tar::Archive, digest: &str) -> Option<&'a [u8]> {
    tar::body(bytes, find_blob(archive, digest)?)
}

fn find_blob<'a>(archive: &'a tar::Archive, digest: &str) -> Option<&'a tar::Member> {
    let name = blob_path(digest)?;
    archive
        .members
        .iter()
        .find(|member| is_name(&member.name, &name))
}

fn find<'a>(archive: &'a tar::Archive, name: &str) -> Option<&'a tar::Member> {
    archive
        .members
        .iter()
        .find(|member| is_name(&member.name, name))
}

fn is_name(have: &str, want: &str) -> bool {
    have == want || have.strip_prefix("./") == Some(want)
}

fn blob_path(digest: &str) -> Option<String> {
    let hex = blob_digest(digest)?;
    Some(format!("blobs/sha256/{hex}"))
}

fn blob_digest(name: &str) -> Option<&str> {
    let hex = name.strip_prefix("sha256:").or_else(|| {
        name.rsplit('/')
            .next()
            .filter(|tail| name.contains("blobs/sha256/") && tail.len() == 64)
    })?;
    if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(hex)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(block: &[u8]) -> u64 {
        let mut sum = 0u64;
        for (index, &byte) in block.iter().enumerate() {
            if (148..156).contains(&index) {
                sum += u64::from(b' ');
            } else {
                sum += u64::from(byte);
            }
        }
        sum
    }

    fn header(name: &str, size: usize) -> [u8; 512] {
        let mut block = [0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..107].copy_from_slice(b"0000644");
        block[108..115].copy_from_slice(b"0000000");
        block[116..123].copy_from_slice(b"0000000");
        let size_text = format!("{size:011o}");
        block[124..135].copy_from_slice(size_text.as_bytes());
        block[136..147].copy_from_slice(b"00000000000");
        block[156] = b'0';
        block[257..262].copy_from_slice(b"ustar");
        block[263..265].copy_from_slice(b"00");
        let sum = format!("{:06o}\0 ", checksum(&block));
        block[148..156].copy_from_slice(sum.as_bytes());
        block
    }

    fn ustar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in files {
            out.extend_from_slice(&header(name, data.len()));
            out.extend_from_slice(data);
            let rem = data.len() % 512;
            if rem != 0 {
                out.extend(std::iter::repeat(0).take(512 - rem));
            }
        }
        out
    }

    fn jpeg() -> Vec<u8> {
        let mut out = vec![0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 8, 0, 2, 0, 3, 3];
        out.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0, 0xff, 0xd9]);
        out
    }

    #[test]
    fn a_layout_tar_is_an_oci_image() {
        let bytes = ustar(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            (
                "index.json",
                br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#,
            ),
        ]);
        assert!(is_oci(&bytes));
        let image = parse(&bytes).unwrap();
        assert_eq!(image.layout, "1.0.0");
        assert_eq!(image.schema, Some(2));
        let page = page::render("app.tar", &image, false, false, &[], &[]);
        assert!(page.contains("format: oci"), "{page}");
        assert!(page.contains("layout: 1.0.0"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        let json = page::render_json("app.tar", &image, false, &[], &[]);
        assert!(json.contains(r#""format":"oci""#), "{json}");
    }

    #[test]
    fn a_plain_tar_is_not_an_oci_image() {
        let bytes = ustar(&[("hello.txt", b"hi")]);
        assert!(!is_oci(&bytes));
        assert!(parse(&bytes).is_err());
        assert!(crate::step(&bytes, &["hello.txt"], false, false).is_none());
    }

    #[test]
    fn a_broken_index_returns_an_error() {
        let bytes = ustar(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            ("index.json", b"{"),
        ]);
        assert!(is_oci(&bytes));
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn a_layer_tar_keeps_the_config_and_a_nested_jpeg() {
        let photo = ustar(&[("photo.jpg", &jpeg())]);
        let manifest_digest = "a".repeat(64);
        let config_digest = "b".repeat(64);
        let layer_digest = "c".repeat(64);
        let config = br#"{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/bin/sh"],"Cmd":["-c","true"],"WorkingDir":"/","Env":["PATH=/usr/bin"]}}"#;
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config_digest}","size":{config_len}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{layer_digest}","size":{layer_len}}}]}}"#,
            config_len = config.len(),
            layer_len = photo.len(),
        );
        let index = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{manifest_digest}","size":{manifest_len},"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#,
            manifest_len = manifest.len(),
        );
        let bytes = ustar(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            ("index.json", index.as_bytes()),
            (
                &format!("blobs/sha256/{manifest_digest}"),
                manifest.as_bytes(),
            ),
            (&format!("blobs/sha256/{config_digest}"), config),
            (&format!("blobs/sha256/{layer_digest}"), photo.as_slice()),
        ]);
        let image = parse(&bytes).unwrap();
        assert_eq!(image.architecture.as_deref(), Some("amd64"));
        assert_eq!(image.os.as_deref(), Some("linux"));
        assert_eq!(image.entrypoint, vec!["/bin/sh".to_string()]);
        assert_eq!(image.layers.len(), 1);
        assert!(image.layers[0].offset.is_some());
        let file = crate::open(&bytes, false).unwrap();
        let page = crate::render("app.tar", &file, false, false);
        assert!(page.contains("format: oci"), "{page}");
        assert!(page.contains("architecture: amd64"), "{page}");
        assert!(page.contains("platform: linux/amd64"), "{page}");
        assert!(!page.contains("format: jpeg"), "{page}");
        assert!(!page.contains("format: tar"), "{page}");
        let digest = format!("sha256:{}", "c".repeat(64));
        let layer = crate::step(&bytes, &[&digest], false, false).unwrap();
        assert!(layer.contains("format: tar"), "{layer}");
        assert!(layer.contains("photo.jpg"), "{layer}");
        assert!(!layer.contains("format: jpeg"), "{layer}");
        let photo = crate::step(&bytes, &[&digest, "photo.jpg"], false, false).unwrap();
        assert!(photo.contains("format: jpeg"), "{photo}");
        assert!(photo.contains("width: 3"), "{photo}");
        let facts = crate::facts("app.tar", &file, &crate::current_host());
        assert!(facts.is_err());
    }
}
