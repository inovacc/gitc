package gitwin

import "testing"

func TestSelectMinGit(t *testing.T) {
	assets := []Asset{
		{Name: "Git-2.55.0.2-64-bit.exe"},
		{Name: "MinGit-2.55.0.2-64-bit.zip", URL: "u-amd64"},
		{Name: "MinGit-2.55.0.2-busybox-64-bit.zip", URL: "u-amd64-busybox"},
		{Name: "MinGit-2.55.0.2-32-bit.zip", URL: "u-386"},
		{Name: "MinGit-2.55.0.2-arm64.zip", URL: "u-arm64"},
		{Name: "PortableGit-2.55.0.2-64-bit.7z.exe"},
	}
	tests := []struct {
		arch    string
		wantURL string
		wantErr bool
	}{
		{"amd64", "u-amd64", false}, // prefers non-busybox
		{"386", "u-386", false},
		{"arm64", "u-arm64", false},
		{"mips", "", true}, // unsupported arch
	}
	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			got, err := SelectMinGit(assets, tt.arch)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s", tt.arch)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.URL != tt.wantURL {
				t.Fatalf("URL = %q, want %q", got.URL, tt.wantURL)
			}
		})
	}
}

func TestSelectMinGitBusyboxFallback(t *testing.T) {
	// Only the busybox variant present → it is used as a fallback.
	assets := []Asset{{Name: "MinGit-2.55.0.2-busybox-64-bit.zip", URL: "bb"}}
	got, err := SelectMinGit(assets, "amd64")
	if err != nil || got.URL != "bb" {
		t.Fatalf("busybox fallback failed: got %q err %v", got.URL, err)
	}
}

func TestSanitizeTag(t *testing.T) {
	if s := sanitizeTag("v2.55.0.windows.2"); s != "v2.55.0.windows.2" {
		t.Fatalf("got %q", s)
	}
	if s := sanitizeTag(""); s != "latest" {
		t.Fatalf("empty tag got %q", s)
	}
}
