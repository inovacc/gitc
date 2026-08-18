# gitc

A **git toolkit in Rust**. Two things ship in this crate:

- a **library** — pure-Rust readers for git's on-disk formats, plus an optional
  `git filter-repo` port; and
- a **binary** — a drop-in `git` that **is** git: git's own C source compiled in
  via the C ABI.

```
$ gitc --version
git version 2.55.GIT          # the binary is real git, byte-for-byte
```

## Library

Pure Rust, no external service, no gate — just git formats parsed directly. Only
depends on `flate2` (zlib inflate) and, behind the `scrub` feature, `regex`.

| module | what it does |
|---|---|
| `gitobj`   | read git objects by id — loose first, then packed |
| `gitpack`  | read objects from packfiles (`.git/objects/pack/*.{idx,pack}`) |
| `gitindex` | parse `.git/index` and enumerate the staged blobs |
| `gitwalk`  | enumerate the blobs reachable from a set of commits |
| `gitargs`  | a minimal git argv parser |
| `filterrepo` | a `git filter-repo` port for history rewriting (feature `scrub`) |

```
cargo test                 # runs the library's unit tests
cargo build --features scrub
```

## Binary — git via FFI

git's process entry on Windows is its own `wmain` (`compat/mingw.c`), reached via
`wmainCRTStartup` because the binary is linked with `-municode`. `wmain` performs
all of git's mandatory Windows startup and then calls `main(argc, argv)` with
clean UTF-8 argv. This crate **provides that `main`** (via `#![no_main]` + an
exported `extern "C" fn main`), replacing git's `common-main.c` `main()`. Our
`main` does exactly what git's does — `init_git(argv)` then `cmd_main(argc, argv)`
— passing the original argv straight through. The result is 1:1 git.

```
src/main.rs   the exported extern "C" main → init_git → cmd_main
src/ffi.rs    the two FFI declarations (init_git, cmd_main)
build.rs      merges git.o + builtin/*.o + libgit.a into one archive and links it
vendor/git    git's C source, as a submodule (github.com/git/git)
```

`common-main.o` is deliberately NOT linked (Rust owns `main`); git's `wmain`
lives in `mingw.o` inside the combined git archive.

### Build (binary)

The binary links git's own mingw/gnu-ABI objects, so it **must** be built for a
`*-windows-gnu` target with the msys2 UCRT64 toolchain (the same one that builds
git). The library builds on any host; only the binary needs this.

1. **Toolchain** — install [msys2](https://www.msys2.org/) and the UCRT64 gcc:
   ```
   pacman -S mingw-w64-ucrt-x86_64-gcc
   rustup target add x86_64-pc-windows-gnu
   ```
   `.cargo/config.toml` points the gnu-target linker at
   `C:/msys64/ucrt64/bin/gcc.exe` — override via
   `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER` if yours differs.

2. **git source** — check out the vendored submodule:
   ```
   git submodule update --init --recursive vendor/git
   ```

3. **Build git's C objects** once, in the msys2 UCRT64 shell — note `curl` is
   required (HTTPS transport) so `NO_CURL` is deliberately absent:
   ```
   cd vendor/git
   make -j4 MSYSTEM=MINGW64 NO_RUST=1 NO_OPENSSL=1 NO_EXPAT=1 \
        NO_GETTEXT=1 NO_TCLTK=1 NO_PERL=1 NO_PYTHON=1 git.exe git-remote-http.exe
   ```
   This produces `git.o`, `builtin/*.o`, `libgit.a` (the FFI inputs), and the
   separate `git-remote-http.exe` (installed at run time for https).

4. **Build gitc**:
   ```
   cargo build --release --target x86_64-pc-windows-gnu
   ```

   The runtime needs `libpcre2-8-0.dll` / `zlib1.dll` / `libiconv-2.dll` on PATH,
   and — for **https remotes** — `git-remote-http(s).exe` + its DLL closure + a CA
   bundle installed under the binary's `libexec/git-core`. See **[REQUIREMENTS.md](REQUIREMENTS.md)**
   for the complete build- and run-time spec (toolchain, artifacts, HTTPS helper,
   templates, and the `GITC_*` build env overrides).

## Licensing

The Rust code in this repository is BSD-3-Clause. The built **binary** statically
incorporates git's own C source (`vendor/git`, git/git), which is **GPL-2.0** —
so the distributed binary is governed by git's license. See `vendor/git/COPYING`.
The **library** links no git C and is BSD-3-Clause on its own.
