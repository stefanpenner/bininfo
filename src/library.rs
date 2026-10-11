/*
---
why: This file names what a common library provides.
uses: bininfo
how: The needed list calls this file for each library name.
An unknown name gets no note.
---
*/

//! Notes for common library names. An unknown name returns none.

pub fn note(name: &str) -> Option<&'static str> {
    match stem(name).as_str() {
        "libc" => Some(
            "The C library. It provides stdio, memory, and system calls. https://man7.org/linux/man-pages/man7/libc.7.html",
        ),
        "libm" => Some(
            "Floating-point math functions. https://man7.org/linux/man-pages/man3/libm.3.html",
        ),
        "libdl" => Some(
            "dlopen and dlsym. The file can open a library later. https://man7.org/linux/man-pages/man3/dlopen.3.html",
        ),
        "libpthread" => Some(
            "POSIX thread functions. https://man7.org/linux/man-pages/man7/pthreads.7.html",
        ),
        "librt" => Some("Clock and timer functions."),
        "libresolv" => Some(
            "DNS lookup functions. https://man7.org/linux/man-pages/man3/resolver.3.html",
        ),
        "libcrypt" => Some(
            "Password hash functions. https://man7.org/linux/man-pages/man3/crypt.3.html",
        ),
        "libgcc_s" => Some("GCC unwind and integer helpers."),
        "libstdc++" => Some(
            "The GNU C++ standard library. https://gcc.gnu.org/onlinedocs/libstdc++/manual/index.html",
        ),
        "libc++" => Some("The LLVM C++ standard library. https://libcxx.llvm.org/"),
        "libc++abi" => Some("LLVM C++ exceptions and run-time type info."),
        "libz" => Some("zlib compression. https://zlib.net/manual.html"),
        "libssl" => Some("TLS for OpenSSL. https://docs.openssl.org/master/man7/ssl/"),
        "libcrypto" => Some("Cryptography for OpenSSL. https://docs.openssl.org/master/man7/crypto/"),
        "libcurl" => Some("URL transfers for curl. https://curl.se/libcurl/"),
        "libsqlite3" => Some("The SQLite database library. https://www.sqlite.org/cintro.html"),
        "libsystem" => Some("libc, libm, and pthread. macOS keeps those libraries in this file."),
        "libobjc" => Some(
            "The Objective-C runtime. https://developer.apple.com/documentation/objectivec",
        ),
        "corefoundation" => Some(
            "Core Foundation types, strings, and collections. https://developer.apple.com/documentation/corefoundation",
        ),
        "foundation" => Some(
            "Objective-C base classes. https://developer.apple.com/documentation/foundation",
        ),
        "appkit" => Some("macOS windows and menus. https://developer.apple.com/documentation/appkit"),
        "uikit" => Some("iOS views. https://developer.apple.com/documentation/uikit"),
        "security" => Some(
            "Keychain and certificates. https://developer.apple.com/documentation/security",
        ),
        "coregraphics" => Some("2D drawing on Apple platforms."),
        "cfnetwork" => Some("Network transfers on Apple platforms."),
        "kernel32" => Some(
            "Base Windows functions for files, processes, and memory. https://learn.microsoft.com/en-us/windows/win32/api/winbase/",
        ),
        "kernelbase" => Some("Lower-level Windows base functions."),
        "ntdll" => Some("Native Windows system calls."),
        "user32" => Some(
            "Windows and message functions. https://learn.microsoft.com/en-us/windows/win32/api/winuser/",
        ),
        "gdi32" => Some(
            "Windows graphics functions. https://learn.microsoft.com/en-us/windows/win32/api/wingdi/",
        ),
        "advapi32" => Some("Registry, services, and security functions."),
        "shell32" => Some("Windows shell functions."),
        "ole32" | "oleaut32" | "combase" => Some("COM object functions."),
        "ws2_32" | "wsock32" => Some(
            "Windows sockets. https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2",
        ),
        "msvcrt" | "ucrtbase" => Some(
            "The Windows C runtime. https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features",
        ),
        "vcruntime140" | "vcruntime140_1" => Some("The Microsoft C runtime support library."),
        "msvcp140" => Some("The Microsoft C++ standard library."),
        "bcrypt" => Some("Windows cryptography functions."),
        "crypt32" => Some("Windows certificate functions."),
        "shlwapi" => Some("Windows path and string helpers."),
        "comctl32" => Some("Windows common controls."),
        _ => None,
    }
}

fn stem(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    if let Some(rest) = lower.strip_suffix(".dll") {
        return rest.to_string();
    }
    if let Some(head) = strip_so(&lower) {
        return head.to_string();
    }
    if let Some(rest) = lower.strip_suffix(".dylib") {
        return strip_dylib_version(rest).to_string();
    }
    lower
}

fn strip_so(name: &str) -> Option<&str> {
    if let Some(index) = name.find(".so.") {
        return Some(&name[..index]);
    }
    name.strip_suffix(".so")
}

fn strip_dylib_version(name: &str) -> &str {
    let Some((head, tail)) = name.rsplit_once('.') else {
        return name;
    };
    let one_letter = tail.len() == 1 && tail.chars().all(|c| c.is_ascii_alphabetic());
    let digits = !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit());
    if one_letter || digits {
        return strip_dylib_version(head);
    }
    name
}

#[cfg(test)]
mod tests {
    use super::note;

    #[test]
    fn common_names_have_a_note_and_other_names_do_not() {
        let libc = note("/lib/x86_64-linux-gnu/libc.so.6").unwrap();
        assert!(libc.contains("The C library."), "{libc}");
        assert!(
            libc.contains("https://man7.org/linux/man-pages/man7/libc.7.html"),
            "{libc}"
        );
        assert!(note("libdl.so.2").unwrap().contains("dlopen"));
        assert!(note("libdl2.so").is_none());
        assert!(note("libtiny.so").is_none());
        assert!(note("my.socket").is_none());
        let system = note("/usr/lib/libSystem.B.dylib").unwrap();
        assert!(system.contains("libc, libm, and pthread."), "{system}");
        let cxx = note("@rpath/libc++.1.dylib").unwrap();
        assert!(cxx.contains("LLVM C++ standard library."), "{cxx}");
        let kernel = note("KERNEL32.dll").unwrap();
        assert!(kernel.contains("files, processes, and memory."), "{kernel}");
        assert!(
            kernel.contains("https://learn.microsoft.com/en-us/windows/win32/api/winbase/"),
            "{kernel}"
        );
        assert!(note("tiny.dll").is_none());
        assert!(note("CoreFoundation")
            .unwrap()
            .contains("strings, and collections."));
    }
}
