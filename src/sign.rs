/*
---
why: This file checks one Mach-O or PE signature.
uses: bininfo
how: bininfo calls this file with the file bytes.
The result is absent, valid, or invalid.
---
*/

//! One signature verdict for one file.
//! Mach-O checks each code page hash.
//! PE checks the Authenticode digest.
//! ELF has no signature record.

use crate::elf::header as elf_header;
use crate::hash::{self, Sha1, Sha256, Sha512};
use crate::macho::header::{self as macho_header, Class, Data, Image};
use crate::pe::header::{self as pe_header, Class as PeClass};
use crate::pe::load::{self as pe_load};

const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_REQ: u32 = 0x8000_0000;
const EMBEDDED: u32 = 0xfade_0cc0;
const CODE_DIRECTORY: u32 = 0xfade_0c02;
const BLOB_WRAPPER: u32 = 0xfade_0b01;
const SLOT_CODE: u32 = 0;
const SLOT_ALTERNATE: u32 = 0x1000;
const SLOT_ALTERNATE_MAX: u32 = 5;
const SLOT_SIGNATURE: u32 = 0x1_0000;
const ADHOC: u32 = 0x2;
const CODE_LIMIT_64: u32 = 0x20300;
const SLOT_CAP: u32 = 64;
const PAGE_CAP: u64 = 1_048_576;
const PAGE_SHIFT_MAX: u8 = 24;
const CMD_CAP: u32 = 4096;
const SECURITY_DIR: u32 = 4;

const SHA1_OID: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA384_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const SHA512_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const SPC_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
const DIGEST_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

/// One signature verdict. `status` is absent, valid, or invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sign {
    pub status: &'static str,
    pub kind: &'static str,
    pub reason: String,
}

/// Read the signature in `bytes`. A bad blob returns invalid. It does not panic.
pub fn read(bytes: &[u8]) -> Sign {
    if macho_header::is_macho(bytes) {
        return macho_sign(bytes);
    }
    if elf_header::is_elf(bytes) {
        return absent("none", "ELF has no signature record.");
    }
    if pe_header::is_pe(bytes) {
        return pe_sign(bytes);
    }
    absent("none", "This file has no signature record.")
}

fn absent(kind: &'static str, reason: &str) -> Sign {
    Sign {
        status: "absent",
        kind,
        reason: reason.to_string(),
    }
}

fn valid(kind: &'static str, reason: &str) -> Sign {
    Sign {
        status: "valid",
        kind,
        reason: reason.to_string(),
    }
}

fn invalid(kind: &'static str, reason: &str) -> Sign {
    Sign {
        status: "invalid",
        kind,
        reason: reason.to_string(),
    }
}

fn macho_sign(bytes: &[u8]) -> Sign {
    let image = match macho_header::parse(bytes) {
        Ok(image) => image,
        Err(_) => return invalid("macho", "The Mach-O header is truncated."),
    };
    match image {
        Image::Thin(thin) => check_slice(
            bytes,
            0,
            bytes.len() as u64,
            thin.class,
            thin.data,
            thin.ncmds,
            thin.sizeofcmds,
            None,
        ),
        Image::Fat(fat) => fat_sign(bytes, &fat),
    }
}

fn fat_sign(bytes: &[u8], fat: &macho_header::Fat) -> Sign {
    if fat.arches.is_empty() {
        return invalid("macho", "The fat header has no slice.");
    }
    let mut saw_absent = false;
    let mut reasons = Vec::new();
    for (index, arch) in fat.arches.iter().enumerate() {
        let end = match arch.offset.checked_add(arch.size) {
            Some(end) if end <= bytes.len() as u64 && arch.size > 0 => end,
            _ => return invalid("macho", "A fat slice is truncated."),
        };
        let slice = &bytes[arch.offset as usize..end as usize];
        let thin = match macho_header::parse(slice) {
            Ok(Image::Thin(thin)) => thin,
            _ => return invalid("macho", "A fat slice is truncated."),
        };
        let one = check_slice(
            bytes,
            arch.offset,
            arch.size,
            thin.class,
            thin.data,
            thin.ncmds,
            thin.sizeofcmds,
            None,
        );
        match one.status {
            "valid" => reasons.push(one.reason),
            "absent" => saw_absent = true,
            _ => {
                return invalid(
                    "macho",
                    &prefix(Some(&format!("Slice {index}")), &one.reason),
                );
            }
        }
    }
    if !reasons.is_empty() && saw_absent {
        return invalid("macho", "One slice has no signature.");
    }
    if let Some(first) = reasons.first() {
        if reasons.iter().all(|reason| reason == first) {
            return valid("macho", first);
        }
        let text = reasons
            .iter()
            .enumerate()
            .map(|(index, reason)| format!("Slice {index}: {reason}"))
            .collect::<Vec<_>>()
            .join(" ");
        return valid("macho", &text);
    }
    absent("macho", "No LC_CODE_SIGNATURE command.")
}

fn check_slice(
    file: &[u8],
    offset: u64,
    size: u64,
    class: Class,
    data: Data,
    ncmds: u32,
    sizeofcmds: u32,
    label: Option<&str>,
) -> Sign {
    let Some(end) = offset.checked_add(size) else {
        return invalid("macho", "A slice offset is past the file.");
    };
    if end > file.len() as u64 {
        return invalid("macho", "A slice is past the file.");
    }
    let slice = &file[offset as usize..end as usize];
    let Some((dataoff, datasize)) = signature_range(slice, class, data, ncmds, sizeofcmds) else {
        return absent("macho", &prefix(label, "No LC_CODE_SIGNATURE command."));
    };
    let start = dataoff as usize;
    let stop = match start.checked_add(datasize as usize) {
        Some(stop) if stop <= slice.len() && datasize >= 12 => stop,
        _ => return invalid("macho", &prefix(label, "The code signature is truncated.")),
    };
    let blob = &slice[start..stop];
    match check_superblob(slice, blob) {
        Ok(reason) => valid("macho", &prefix(label, &reason)),
        Err(reason) => invalid("macho", &prefix(label, &reason)),
    }
}

fn prefix(label: Option<&str>, reason: &str) -> String {
    match label {
        Some(label) => format!("{label}: {reason}"),
        None => reason.to_string(),
    }
}

fn signature_range(
    slice: &[u8],
    class: Class,
    data: Data,
    ncmds: u32,
    sizeofcmds: u32,
) -> Option<(u32, u32)> {
    let start = class.header_bytes() as usize;
    let end = start.saturating_add(sizeofcmds as usize).min(slice.len());
    let mut at = start;
    let mut seen = 0u32;
    while seen < ncmds.min(CMD_CAP) {
        let cmd = macho_header::u32_at(slice, at, data)?;
        let size = macho_header::u32_at(slice, at + 4, data)?;
        if size < 8 {
            return None;
        }
        let next = at.checked_add(size as usize)?;
        if next > end || next > slice.len() {
            return None;
        }
        if cmd & !LC_REQ == LC_CODE_SIGNATURE && size >= 16 {
            let dataoff = macho_header::u32_at(slice, at + 8, data)?;
            let datasize = macho_header::u32_at(slice, at + 12, data)?;
            return Some((dataoff, datasize));
        }
        at = next;
        seen += 1;
    }
    None
}

fn check_superblob(slice: &[u8], blob: &[u8]) -> Result<String, String> {
    let magic = be_u32(blob, 0).ok_or_else(|| "The code signature is truncated.".to_string())?;
    if magic != EMBEDDED {
        return Err("The code signature magic is wrong.".into());
    }
    let length =
        be_u32(blob, 4).ok_or_else(|| "The code signature is truncated.".to_string())? as usize;
    if length > blob.len() || length < 12 {
        return Err("The code signature is truncated.".into());
    }
    let count = be_u32(blob, 8).ok_or_else(|| "The code signature is truncated.".to_string())?;
    if count > SLOT_CAP {
        return Err("There are too many signature slots.".into());
    }
    let index_end = 12usize.saturating_add((count as usize).saturating_mul(8));
    if index_end > length {
        return Err("The code signature is truncated.".into());
    }
    let body = &blob[..length];
    let mut directories = Vec::new();
    let mut wrapper = None;
    for index in 0..count as usize {
        let at = 12 + index * 8;
        let kind =
            be_u32(body, at).ok_or_else(|| "The code signature is truncated.".to_string())?;
        let off = be_u32(body, at + 4)
            .ok_or_else(|| "The code signature is truncated.".to_string())?
            as usize;
        if off >= length {
            return Err("The code signature is truncated.".into());
        }
        let slot = &body[off..];
        if is_directory_slot(kind) {
            directories.push(slot);
        } else if kind == SLOT_SIGNATURE {
            wrapper = Some(slot);
        }
    }
    if directories.is_empty() {
        return Err("The code signature has no code directory.".into());
    }
    let mut reason = None;
    for directory in &directories {
        let one = check_directory(slice, body, directory, wrapper)?;
        if reason.is_none() {
            reason = Some(one);
        }
    }
    Ok(reason.unwrap_or_else(|| "Code page hashes match.".into()))
}

fn is_directory_slot(kind: u32) -> bool {
    kind == SLOT_CODE || (kind >= SLOT_ALTERNATE && kind - SLOT_ALTERNATE < SLOT_ALTERNATE_MAX)
}

fn check_directory(
    slice: &[u8],
    superblob: &[u8],
    directory: &[u8],
    wrapper: Option<&[u8]>,
) -> Result<String, String> {
    let magic =
        be_u32(directory, 0).ok_or_else(|| "The code directory is truncated.".to_string())?;
    if magic != CODE_DIRECTORY {
        return Err("The code directory magic is wrong.".into());
    }
    let length = be_u32(directory, 4)
        .ok_or_else(|| "The code directory is truncated.".to_string())? as usize;
    if length > directory.len() || length < 44 {
        return Err("The code directory is truncated.".into());
    }
    let cd = &directory[..length];
    let version = be_u32(cd, 8).ok_or_else(|| "The code directory is truncated.".to_string())?;
    let flags = be_u32(cd, 12).ok_or_else(|| "The code directory is truncated.".to_string())?;
    let hash_off =
        be_u32(cd, 16).ok_or_else(|| "The code directory is truncated.".to_string())? as usize;
    let n_special = be_u32(cd, 24).ok_or_else(|| "The code directory is truncated.".to_string())?;
    let n_code =
        be_u32(cd, 28).ok_or_else(|| "The code directory is truncated.".to_string())? as u64;
    let mut code_limit =
        be_u32(cd, 32).ok_or_else(|| "The code directory is truncated.".to_string())? as u64;
    let hash_size = cd[36] as usize;
    let hash_type = cd[37];
    let page_shift = cd[39];
    if version >= CODE_LIMIT_64 && length >= 64 {
        if let Some(wide) = be_u64(cd, 56) {
            if wide != 0 {
                code_limit = wide;
            }
        }
    }
    if code_limit == 0 || code_limit > slice.len() as u64 {
        return Err("The code limit is past the end of the file.".into());
    }
    if page_shift > PAGE_SHIFT_MAX || hash_size == 0 || hash_size > 64 {
        return Err("The page size is outside the checked range.".into());
    }
    let page = 1u64 << page_shift;
    if n_code > PAGE_CAP {
        return Err("There are too many code pages.".into());
    }
    let pages = code_limit.div_ceil(page);
    if n_code != pages {
        return Err("The code slot count does not match the code limit.".into());
    }
    let special = n_special as usize;
    let hash_start = hash_off
        .checked_sub(special.saturating_mul(hash_size))
        .ok_or_else(|| "The code directory is truncated.".to_string())?;
    let hash_end = hash_off.saturating_add((n_code as usize).saturating_mul(hash_size));
    if hash_end > cd.len() || hash_start > cd.len() {
        return Err("The code directory is truncated.".into());
    }
    for index in 0..n_code {
        let start = (index * page) as usize;
        let stop = ((index + 1) * page).min(code_limit) as usize;
        let got = digest(hash_type, hash_size, &slice[start..stop])?;
        let at = hash_off + (index as usize) * hash_size;
        if cd[at..at + hash_size] != got[..] {
            return Err(format!("Code page {index} hash does not match."));
        }
    }
    let mut external = false;
    for slot in 1..=special {
        let at = hash_off - slot * hash_size;
        let stored = &cd[at..at + hash_size];
        if let Some(blob) = slot_blob(superblob, slot as u32) {
            let got = digest(hash_type, hash_size, blob)?;
            if stored != got.as_slice() {
                return Err(format!("Slot {slot} hash does not match."));
            }
        } else if stored.iter().any(|byte| *byte != 0) {
            external = true;
        }
    }
    let adhoc = flags & ADHOC != 0;
    let mut reason = if adhoc {
        "Ad-hoc signature. Code page hashes match.".to_string()
    } else {
        "Code page hashes match.".to_string()
    };
    match wrapper {
        Some(wrapper) => {
            let digest_bytes = signer_digest(wrapper)
                .ok_or_else(|| "The signer blob has no digest.".to_string())?;
            let got = digest_len(digest_bytes.len(), cd)?;
            if got != digest_bytes {
                return Err("The signer digest does not match the code directory.".into());
            }
            if !adhoc {
                reason = "Code page hashes match. The signer digest matches the code directory. This check does not use the signer key.".into();
            }
        }
        None if !adhoc => return Err("The signature has no signer blob.".into()),
        None => {}
    }
    if external {
        reason.push_str(" An external slot is not in this file.");
    }
    Ok(reason)
}

fn slot_blob<'a>(superblob: &'a [u8], kind: u32) -> Option<&'a [u8]> {
    let count = be_u32(superblob, 8)? as usize;
    if count > SLOT_CAP as usize {
        return None;
    }
    for index in 0..count {
        let at = 12 + index * 8;
        if be_u32(superblob, at)? != kind {
            continue;
        }
        let off = be_u32(superblob, at + 4)? as usize;
        let slot = superblob.get(off..)?;
        let length = be_u32(slot, 4)? as usize;
        if length < 8 || length > slot.len() {
            return None;
        }
        return Some(&slot[..length]);
    }
    None
}

fn signer_digest(wrapper: &[u8]) -> Option<&[u8]> {
    let magic = be_u32(wrapper, 0)?;
    if magic != BLOB_WRAPPER {
        return None;
    }
    let length = be_u32(wrapper, 4)? as usize;
    if length > wrapper.len() || length < 8 {
        return None;
    }
    message_digest(&wrapper[8..length])
}

fn message_digest(der: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    while let Some(pos) = find_from(der, DIGEST_OID, at) {
        let header = pos.checked_sub(2)?;
        if der.get(header..pos) == Some(&[0x06, 0x09]) {
            if let Some(oct) = digest_octet(&der[pos + DIGEST_OID.len()..]) {
                return Some(oct);
            }
        }
        at = pos + 1;
    }
    None
}

fn digest_octet(bytes: &[u8]) -> Option<&[u8]> {
    let (tag, content, _) = read_tlv(bytes)?;
    if tag != 0x31 {
        return None;
    }
    let (tag, oct, _) = read_tlv(content)?;
    if tag == 0x04 && matches!(oct.len(), 20 | 32 | 48 | 64) {
        return Some(oct);
    }
    None
}

fn digest(hash_type: u8, hash_size: usize, data: &[u8]) -> Result<Vec<u8>, String> {
    let full = match hash_type {
        1 => hash::sha1(data).to_vec(),
        2 | 3 => hash::sha256(data).to_vec(),
        4 => hash::sha384(data).to_vec(),
        5 => hash::sha512(data).to_vec(),
        other => return Err(format!("Hash type {other} is unknown.")),
    };
    if hash_type == 3 {
        if hash_size != 20 || full.len() < 20 {
            return Err("The hash size does not match the hash type.".into());
        }
        return Ok(full[..20].to_vec());
    }
    if full.len() != hash_size {
        return Err("The hash size does not match the hash type.".into());
    }
    Ok(full)
}

fn digest_len(len: usize, cd: &[u8]) -> Result<Vec<u8>, String> {
    let full = match len {
        20 => hash::sha1(cd).to_vec(),
        32 => hash::sha256(cd).to_vec(),
        48 => hash::sha384(cd).to_vec(),
        64 => hash::sha512(cd).to_vec(),
        _ => return Err("The signer blob has no digest.".into()),
    };
    Ok(full)
}

fn pe_sign(bytes: &[u8]) -> Sign {
    let header = match pe_header::parse(bytes) {
        Ok(header) => header,
        Err(_) => return absent("none", "This file has no signature record."),
    };
    let Some((off, size)) = pe_load::data_dir(bytes, &header, SECURITY_DIR) else {
        return absent("pe", "No certificate table.");
    };
    let Some(der) = cert_der(bytes, off, size) else {
        return invalid("pe", "The certificate table is truncated.");
    };
    let Some((alg, digest)) = spc_digest(der) else {
        return invalid("pe", "The certificate table has no digest.");
    };
    let got = match authenticode(bytes, &header, alg) {
        Ok(got) => got,
        Err(reason) => return invalid("pe", reason),
    };
    if got == digest {
        let name = match alg {
            1 => "SHA-1",
            2 => "SHA-256",
            4 => "SHA-384",
            5 => "SHA-512",
            _ => "hash",
        };
        return valid("pe", &format!("The Authenticode {name} digest matches."));
    }
    invalid("pe", "The Authenticode digest does not match.")
}

fn cert_der(bytes: &[u8], off: u32, size: u32) -> Option<&[u8]> {
    let start = off as usize;
    let stop = start.checked_add(size as usize)?;
    if stop > bytes.len() || size < 8 {
        return None;
    }
    let win = &bytes[start..stop];
    let dw = u32::from_le_bytes(win[0..4].try_into().ok()?) as usize;
    if dw < 8 || dw > win.len() {
        return None;
    }
    let kind = u16::from_le_bytes(win[6..8].try_into().ok()?);
    if kind != 2 {
        return None;
    }
    Some(&win[8..dw])
}

fn authenticode(
    bytes: &[u8],
    header: &pe_header::Header,
    alg: u8,
) -> Result<Vec<u8>, &'static str> {
    let opt = header.opt_off as usize;
    let (checksum, dir) = match header.class {
        PeClass::Pe32 => (opt + 64, opt + 96 + 32),
        PeClass::Pe32Plus => (opt + 64, opt + 112 + 32),
        PeClass::Coff => return Err("No certificate table."),
    };
    let headers = header.size_of_headers as usize;
    if checksum + 4 > bytes.len()
        || dir + 8 > bytes.len()
        || headers > bytes.len()
        || headers < dir + 8
    {
        return Err("The certificate table is truncated.");
    }
    let cert_off =
        pe_header::u32_at(bytes, dir).ok_or("The certificate table is truncated.")? as usize;
    let cert_size =
        pe_header::u32_at(bytes, dir + 4).ok_or("The certificate table is truncated.")? as usize;
    let cert_end = cert_off
        .checked_add(cert_size)
        .ok_or("The certificate table is truncated.")?;
    if cert_end > bytes.len() {
        return Err("The certificate table is truncated.");
    }
    let mut dig = Dig::new(alg).ok_or("Hash type 0 is unknown.")?;
    dig.update(&bytes[..checksum]);
    dig.update(&bytes[checksum + 4..dir]);
    dig.update(&bytes[dir + 8..headers]);
    let mut sections = pe_load::sections(bytes, header);
    sections.sort_by_key(|sec| sec.ptr);
    let mut covered = headers;
    for sec in &sections {
        if sec.raw == 0 {
            continue;
        }
        let start = sec.ptr as usize;
        let stop = start
            .checked_add(sec.raw as usize)
            .ok_or("The certificate table is truncated.")?;
        if stop > bytes.len() {
            return Err("The certificate table is truncated.");
        }
        dig.update(&bytes[start..stop]);
        covered = covered.max(stop);
    }
    if cert_off > covered {
        dig.update(&bytes[covered..cert_off]);
    }
    if cert_end < bytes.len() {
        dig.update(&bytes[cert_end..]);
    }
    Ok(dig.finish())
}

fn spc_digest(der: &[u8]) -> Option<(u8, &[u8])> {
    let (tag, body, _) = read_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (_, rest) = read_oid(body)?;
    let (tag, content, _) = read_tlv(rest)?;
    if tag != 0xa0 {
        return None;
    }
    let (tag, signed, _) = read_tlv(content)?;
    if tag != 0x30 {
        return None;
    }
    let (_, _, rest) = read_tlv(signed)?;
    let (_, _, rest) = read_tlv(rest)?;
    let (tag, info, _) = read_tlv(rest)?;
    if tag != 0x30 {
        return None;
    }
    let (oid, rest) = read_oid(info)?;
    if oid != SPC_OID {
        return None;
    }
    let (tag, explicit, _) = read_tlv(rest)?;
    if tag != 0xa0 {
        return None;
    }
    let (tag, spc, _) = read_tlv(explicit)?;
    if tag != 0x30 {
        return None;
    }
    let (_, _, rest) = read_tlv(spc)?;
    let (tag, digest_info, _) = read_tlv(rest)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, alg, rest) = read_tlv(digest_info)?;
    if tag != 0x30 {
        return None;
    }
    let (oid, _) = read_oid(alg)?;
    let (tag, oct, _) = read_tlv(rest)?;
    if tag != 0x04 {
        return None;
    }
    let alg = oid_alg(oid)?;
    Some((alg, oct))
}

fn oid_alg(oid: &[u8]) -> Option<u8> {
    match oid {
        SHA1_OID => Some(1),
        SHA256_OID => Some(2),
        SHA384_OID => Some(4),
        SHA512_OID => Some(5),
        _ => None,
    }
}

enum Dig {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha512),
    Sha512(Sha512),
}

impl Dig {
    fn new(alg: u8) -> Option<Self> {
        match alg {
            1 => Some(Self::Sha1(Sha1::new())),
            2 => Some(Self::Sha256(Sha256::new())),
            4 => Some(Self::Sha384(Sha512::sha384())),
            5 => Some(Self::Sha512(Sha512::sha512())),
            _ => None,
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(hasher) => hasher.update(data),
            Self::Sha256(hasher) => hasher.update(data),
            Self::Sha384(hasher) | Self::Sha512(hasher) => hasher.update(data),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha1(hasher) => hasher.finish().to_vec(),
            Self::Sha256(hasher) => hasher.finish().to_vec(),
            Self::Sha384(hasher) | Self::Sha512(hasher) => hasher.finish(),
        }
    }
}

fn find_from(hay: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= hay.len() {
        return None;
    }
    hay[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|pos| start + pos)
}

fn read_oid(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (tag, content, rest) = read_tlv(bytes)?;
    if tag == 0x06 {
        Some((content, rest))
    } else {
        None
    }
}

fn read_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *bytes.first()?;
    let second = *bytes.get(1)?;
    let (len, header) = if second & 0x80 == 0 {
        (second as usize, 2)
    } else {
        let width = (second & 0x7f) as usize;
        if width == 0 || width > 4 || bytes.len() < 2 + width {
            return None;
        }
        let mut value = 0usize;
        for byte in &bytes[2..2 + width] {
            value = (value << 8) | *byte as usize;
        }
        (value, 2 + width)
    };
    let end = header.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    Some((tag, &bytes[header..end], &bytes[end..]))
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let mut word = [0u8; 4];
    word.copy_from_slice(bytes.get(at..at + 4)?);
    Some(u32::from_be_bytes(word))
}

fn be_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes.get(at..at + 8)?);
    Some(u64::from_be_bytes(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_and_empty_bytes_have_no_signature() {
        assert_eq!(read(b"").status, "absent");
        assert_eq!(read(b"").reason, "This file has no signature record.");
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        let sign = read(&elf);
        assert_eq!(sign.status, "absent");
        assert_eq!(sign.reason, "ELF has no signature record.");
    }

    #[test]
    fn an_adhoc_macho_with_matching_pages_is_valid() {
        let sign = read(&macho(false, true, None));
        assert_eq!(sign.status, "valid", "{}", sign.reason);
        assert_eq!(sign.kind, "macho");
        assert_eq!(sign.reason, "Ad-hoc signature. Code page hashes match.");
    }

    #[test]
    fn a_changed_macho_page_is_invalid() {
        let sign = read(&macho(true, true, None));
        assert_eq!(sign.status, "invalid");
        assert_eq!(sign.reason, "Code page 0 hash does not match.");
    }

    #[test]
    fn a_signer_digest_must_match_the_code_directory() {
        let good = read(&macho(false, false, Some(false)));
        assert_eq!(good.status, "valid", "{}", good.reason);
        assert!(
            good.reason.contains("signer digest matches"),
            "{}",
            good.reason
        );
        assert!(
            good.reason.contains("does not use the signer key"),
            "{}",
            good.reason
        );
        let bad = read(&macho(false, false, Some(true)));
        assert_eq!(bad.status, "invalid");
        assert_eq!(
            bad.reason,
            "The signer digest does not match the code directory."
        );
    }

    #[test]
    fn a_fat_file_keeps_one_shared_signer_reason() {
        let slice = macho(false, false, Some(false));
        let sign = read(&fat_of(&[&slice, &slice]));
        assert_eq!(sign.status, "valid", "{}", sign.reason);
        assert_eq!(
            sign.reason,
            "Code page hashes match. The signer digest matches the code directory. This check does not use the signer key."
        );
    }

    #[test]
    fn a_fat_file_names_each_slice_when_the_reasons_differ() {
        let adhoc = macho(false, true, None);
        let signed = macho(false, false, Some(false));
        let sign = read(&fat_of(&[&adhoc, &signed]));
        assert_eq!(sign.status, "valid", "{}", sign.reason);
        assert!(
            sign.reason
                .contains("Slice 0: Ad-hoc signature. Code page hashes match."),
            "{}",
            sign.reason
        );
        assert!(sign.reason.contains("Slice 1:"), "{}", sign.reason);
        assert!(
            sign.reason.contains("does not use the signer key"),
            "{}",
            sign.reason
        );
    }

    #[test]
    fn a_fat_file_with_one_unsigned_slice_is_invalid() {
        let signed = macho(false, true, None);
        let mut bare = vec![0u8; 32];
        bare[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        let sign = read(&fat_of(&[&signed, &bare]));
        assert_eq!(sign.status, "invalid");
        assert_eq!(sign.reason, "One slice has no signature.");
    }

    #[test]
    fn a_bad_fat_slice_names_that_slice() {
        let good = macho(false, true, None);
        let bad = macho(true, true, None);
        let sign = read(&fat_of(&[&good, &bad]));
        assert_eq!(sign.status, "invalid");
        assert_eq!(sign.reason, "Slice 1: Code page 0 hash does not match.");
    }

    #[test]
    fn a_truncated_code_signature_is_invalid() {
        let mut bytes = macho(false, true, None);
        bytes.truncate(52);
        let sign = read(&bytes);
        assert_eq!(sign.status, "invalid");
        assert_eq!(sign.reason, "The code signature is truncated.");
    }

    #[test]
    fn a_macho_without_a_signature_is_absent() {
        let mut bytes = vec![0u8; 32];
        bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        let sign = read(&bytes);
        assert_eq!(sign.status, "absent");
        assert_eq!(sign.reason, "No LC_CODE_SIGNATURE command.");
    }

    #[test]
    fn an_authenticode_digest_match_is_valid_and_a_byte_change_is_not() {
        let bytes = pe_signed();
        let sign = read(&bytes);
        assert_eq!(sign.status, "valid", "{}", sign.reason);
        assert_eq!(sign.kind, "pe");
        assert_eq!(sign.reason, "The Authenticode SHA-256 digest matches.");
        let mut changed = bytes.clone();
        changed[0x170] ^= 0xff;
        let sign = read(&changed);
        assert_eq!(sign.status, "invalid");
        assert_eq!(sign.reason, "The Authenticode digest does not match.");
    }

    #[test]
    fn a_pe_without_a_certificate_table_is_absent() {
        let bytes = pe_image(0, 0);
        let sign = read(&bytes);
        assert_eq!(sign.status, "absent");
        assert_eq!(sign.reason, "No certificate table.");
    }

    #[test]
    fn hostile_signature_bytes_do_not_panic() {
        let mut samples = vec![
            vec![],
            vec![0u8; 8],
            b"MZ".to_vec(),
            vec![0xcf, 0xfa, 0xed, 0xfe],
        ];
        let mut huge = vec![0u8; 64];
        huge[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        huge[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        samples.push(huge);
        let mut past = macho(false, true, None);
        past[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        samples.push(past);
        for bytes in samples {
            let ran = std::panic::catch_unwind(|| read(&bytes));
            assert!(ran.is_ok(), "signature read panicked");
        }
    }

    fn fat_of(slices: &[&[u8]]) -> Vec<u8> {
        let count = slices.len() as u32;
        let mut header = vec![0u8; 8 + slices.len() * 20];
        header[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        header[4..8].copy_from_slice(&count.to_be_bytes());
        let mut body = Vec::new();
        for (index, slice) in slices.iter().enumerate() {
            let offset = (header.len() + body.len()) as u32;
            let at = 8 + index * 20;
            header[at + 8..at + 12].copy_from_slice(&offset.to_be_bytes());
            header[at + 12..at + 16].copy_from_slice(&(slice.len() as u32).to_be_bytes());
            body.extend_from_slice(slice);
        }
        header.extend(body);
        header
    }

    /// 48 signed bytes, page size 16, then one superblob.
    /// `flip` changes page 0 after the hashes are stored.
    /// `bad_digest` Some(true) stores a wrong signer digest. Some(false) stores the real one.
    fn macho(flip: bool, adhoc: bool, bad_digest: Option<bool>) -> Vec<u8> {
        let cd_len = 44 + 96;
        let wrapper_len = if bad_digest.is_some() { 8 + 47 } else { 0 };
        let count: u32 = if wrapper_len == 0 { 1 } else { 2 };
        let blob_len = 12 + count as usize * 8 + cd_len + wrapper_len;
        let mut file = vec![0u8; 48];
        file[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        file[12..16].copy_from_slice(&2u32.to_le_bytes());
        file[16..20].copy_from_slice(&1u32.to_le_bytes());
        file[20..24].copy_from_slice(&16u32.to_le_bytes());
        file[32..36].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        file[36..40].copy_from_slice(&16u32.to_le_bytes());
        file[40..44].copy_from_slice(&48u32.to_le_bytes());
        file[44..48].copy_from_slice(&(blob_len as u32).to_le_bytes());
        let mut hashes = Vec::new();
        for index in 0..3 {
            let start = index * 16;
            hashes.extend(hash::sha256(&file[start..start + 16]));
        }
        if flip {
            file[8] ^= 0xff;
        }
        let mut cd = vec![0u8; 44];
        put_be(&mut cd, 0, CODE_DIRECTORY);
        put_be(&mut cd, 4, cd_len as u32);
        put_be(&mut cd, 8, 0x20001);
        put_be(&mut cd, 12, if adhoc { ADHOC } else { 0 });
        put_be(&mut cd, 16, 44);
        put_be(&mut cd, 28, 3);
        put_be(&mut cd, 32, 48);
        cd[36] = 32;
        cd[37] = 2;
        cd[39] = 4;
        cd.extend(hashes);
        let mut wrapper = Vec::new();
        if bad_digest.is_some() {
            let mut shown = hash::sha256(&cd);
            if bad_digest == Some(true) {
                shown[0] ^= 0xff;
            }
            let der = digest_der(&shown);
            assert_eq!(der.len(), 47);
            wrapper = vec![0u8; 8];
            put_be(&mut wrapper, 0, BLOB_WRAPPER);
            put_be(&mut wrapper, 4, (8 + der.len()) as u32);
            wrapper.extend(der);
        }
        let mut blob = vec![0u8; 12 + count as usize * 8];
        put_be(&mut blob, 0, EMBEDDED);
        put_be(&mut blob, 4, blob_len as u32);
        put_be(&mut blob, 8, count);
        let cd_off = blob.len() as u32;
        put_be(&mut blob, 12, SLOT_CODE);
        put_be(&mut blob, 16, cd_off);
        blob.extend(cd);
        if !wrapper.is_empty() {
            let wrap_off = blob.len() as u32;
            put_be(&mut blob, 20, SLOT_SIGNATURE);
            put_be(&mut blob, 24, wrap_off);
            blob.extend(wrapper);
        }
        assert_eq!(blob.len(), blob_len);
        file.extend(blob);
        file
    }

    fn digest_der(digest: &[u8]) -> Vec<u8> {
        let mut der = vec![0x06, 0x09];
        der.extend_from_slice(DIGEST_OID);
        der.push(0x31);
        der.push((2 + digest.len()) as u8);
        der.push(0x04);
        der.push(digest.len() as u8);
        der.extend(digest);
        der
    }

    fn put_be(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn pe_signed() -> Vec<u8> {
        let mut bytes = pe_image(0x180, 0);
        let digest = authenticode(&bytes, &pe_header::parse(&bytes).unwrap(), 2).unwrap();
        let der = spc_der(&digest);
        let padded = (8 + der.len() + 7) & !7;
        bytes.resize(0x180 + padded, 0);
        bytes[0x180..0x184].copy_from_slice(&(padded as u32).to_le_bytes());
        bytes[0x184..0x186].copy_from_slice(&0x0200u16.to_le_bytes());
        bytes[0x186..0x188].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x188..0x188 + der.len()].copy_from_slice(&der);
        let opt = 0x58usize;
        put_le(&mut bytes, opt + 144, 0x180);
        put_le(&mut bytes, opt + 148, padded as u32);
        bytes
    }

    fn pe_image(cert_off: u32, cert_size: u32) -> Vec<u8> {
        let opt_size = 240u16;
        let lfanew = 0x40u32;
        let opt = (lfanew + 24) as usize;
        let section = opt + opt_size as usize;
        let body = 0x170usize;
        let mut blob = vec![0u8; body + 16];
        blob[0] = b'M';
        blob[1] = b'Z';
        put_le(&mut blob, 0x3c, lfanew);
        blob[lfanew as usize..lfanew as usize + 4].copy_from_slice(b"PE\0\0");
        let coff = (lfanew + 4) as usize;
        put_u16(&mut blob, coff, 0x8664);
        put_u16(&mut blob, coff + 2, 1);
        put_u16(&mut blob, coff + 16, opt_size);
        put_u16(&mut blob, coff + 18, 0x22);
        put_u16(&mut blob, opt, 0x20b);
        put_le(&mut blob, opt + 16, 0x1000);
        put_le(&mut blob, opt + 60, body as u32);
        put_le(&mut blob, opt + 108, 16);
        if cert_off != 0 {
            put_le(&mut blob, opt + 144, cert_off);
            put_le(&mut blob, opt + 148, cert_size);
        }
        blob[section..section + 5].copy_from_slice(b".text");
        put_le(&mut blob, section + 8, 16);
        put_le(&mut blob, section + 12, 0x1000);
        put_le(&mut blob, section + 16, 16);
        put_le(&mut blob, section + 20, body as u32);
        blob[body..body + 5].copy_from_slice(b"hello");
        blob
    }

    fn spc_der(digest: &[u8]) -> Vec<u8> {
        let alg = seq(&cat(&[&tlv(0x06, SHA256_OID), &tlv(0x05, &[])]));
        let digest_info = seq(&cat(&[&alg, &tlv(0x04, digest)]));
        let data = seq(&tlv(
            0x06,
            &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f],
        ));
        let spc = seq(&cat(&[&data, &digest_info]));
        let content = seq(&cat(&[&tlv(0x06, SPC_OID), &tlv(0xa0, &spc)]));
        let algs = tlv(0x31, &alg);
        let signed = seq(&cat(&[&tlv(0x02, &[0x01]), &algs, &content]));
        let signed_data = tlv(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02],
        );
        seq(&cat(&[&signed_data, &tlv(0xa0, &signed)]))
    }

    fn seq(body: &[u8]) -> Vec<u8> {
        tlv(0x30, body)
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else {
            out.push(0x81);
            out.push(body.len() as u8);
        }
        out.extend(body);
        out
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            out.extend(*part);
        }
        out
    }

    fn put_le(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u16(buf: &mut [u8], at: usize, value: u16) {
        buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
}
