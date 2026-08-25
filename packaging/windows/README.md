# Windows installer

The NSIS package installs `gitc` as the public `git` command and bundles a
complete Git-for-Windows tree as a private backend. The backend remains present
because `gitc scrub` uses Git's fast-export/fast-import and helper commands.

Build from a Git-for-Windows distribution directory:

```powershell
.packaging\windows\build-nsis.ps1 `
  -GitcExe .\target\x86_64-pc-windows-gnu\release\gitc.exe `
  -GitBackend 'C:\Program Files\Git'
```

The backend directory must contain the normal Git-for-Windows layout, including
`cmd\git.exe`, `mingw64\bin`, `mingw64\libexec\git-core`, `usr\bin`, and the
associated templates/share files. NSIS must be installed with `makensis.exe` on
`PATH`.

The installer prepends the public `gitc` bin directory to the machine PATH and
registers `GITC_GIT_BACKEND` to the bundled backend. It does not uninstall or
delete another Git installation.
