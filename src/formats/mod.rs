/*
---
why: This file routes each extra file type.
uses: bininfo
how: bininfo calls open after the start-file checks.
Each type folder adds one arm here.
This file does not parse those bytes.
---
*/

//! Extra file types. ELF, Mach-O, and PE stay outside this folder.
//! Each type adds one arm in `open`. A type here has no start claim.

pub mod ar;
pub mod chrome;
pub mod cpio;
pub mod dmg;
pub mod isobmff;
pub mod jpeg;
pub mod mpq;
pub mod sevenz;
pub mod tar;
pub mod tiff;
pub mod wasm;
pub mod zip;

/// One extra file. The start-file enum does not grow for a new type.
pub enum File {
    Ar(ar::Archive),
    Cpio(cpio::Archive),
    Dmg(dmg::Image),
    Isobmff(isobmff::Movie),
    Jpeg(jpeg::Image),
    Mpq(mpq::Archive),
    Sevenz(sevenz::Archive),
    Tar(tar::Archive),
    Tiff(tiff::Image),
    Wasm(wasm::Module),
    Zip(zip::Archive),
}

/// Read one extra file.
/// `None` means the bytes match no type here.
/// `Some(Err)` means the bytes match a type and the parse failed.
pub fn open(bytes: &[u8]) -> Option<Result<File, String>> {
    // A strong prefix wins.
    // A koly trailer wins over a zip end record.
    // A disk image can hold that record.
    // ustar sits at offset 257, so tar is last.
    if mpq::is_mpq(bytes) {
        return Some(mpq::parse(bytes).map(File::Mpq));
    }
    if wasm::is_wasm(bytes) {
        return Some(wasm::parse(bytes).map(File::Wasm));
    }
    if ar::is_ar(bytes) {
        return Some(ar::parse(bytes).map(File::Ar));
    }
    if sevenz::is_sevenz(bytes) {
        return Some(sevenz::parse(bytes).map(File::Sevenz));
    }
    if cpio::is_cpio(bytes) {
        return Some(cpio::parse(bytes).map(File::Cpio));
    }
    if jpeg::is_jpeg(bytes) {
        return Some(jpeg::parse(bytes).map(File::Jpeg));
    }
    if tiff::is_tiff(bytes) {
        return Some(tiff::parse(bytes).map(File::Tiff));
    }
    if isobmff::is_isobmff(bytes) {
        return Some(isobmff::parse(bytes).map(File::Isobmff));
    }
    if dmg::is_dmg(bytes) {
        return Some(dmg::parse(bytes).map(File::Dmg));
    }
    if zip::is_zip(bytes) {
        return Some(zip::parse(bytes).map(File::Zip));
    }
    if tar::is_tar(bytes) {
        return Some(tar::parse(bytes).map(File::Tar));
    }
    None
}

/// Print one extra file with the same page shape as a start file.
pub fn render(path: &str, file: &File, json: bool, color: bool) -> String {
    match file {
        File::Ar(archive) => {
            if json {
                ar::page::render_json(path, archive)
            } else {
                ar::page::render(path, archive, color)
            }
        }
        File::Cpio(archive) => {
            if json {
                cpio::page::render_json(path, archive)
            } else {
                cpio::page::render(path, archive, color)
            }
        }
        File::Dmg(image) => {
            if json {
                dmg::page::render_json(path, image)
            } else {
                dmg::page::render(path, image, color)
            }
        }
        File::Isobmff(movie) => {
            if json {
                isobmff::page::render_json(path, movie)
            } else {
                isobmff::page::render(path, movie, color)
            }
        }
        File::Jpeg(image) => {
            if json {
                jpeg::page::render_json(path, image)
            } else {
                jpeg::page::render(path, image, color)
            }
        }
        File::Mpq(archive) => {
            if json {
                mpq::page::render_json(path, archive)
            } else {
                mpq::page::render(path, archive, color)
            }
        }
        File::Sevenz(archive) => {
            if json {
                sevenz::page::render_json(path, archive)
            } else {
                sevenz::page::render(path, archive, color)
            }
        }
        File::Tar(archive) => {
            if json {
                tar::page::render_json(path, archive)
            } else {
                tar::page::render(path, archive, color)
            }
        }
        File::Tiff(image) => {
            if json {
                tiff::page::render_json(path, image)
            } else {
                tiff::page::render(path, image, color)
            }
        }
        File::Wasm(module) => {
            if json {
                wasm::page::render_json(path, module)
            } else {
                wasm::page::render(path, module, color)
            }
        }
        File::Zip(archive) => {
            if json {
                zip::page::render_json(path, archive)
            } else {
                zip::page::render(path, archive, color)
            }
        }
    }
}
