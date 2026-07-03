module github.com/joestump/reduit

go 1.26.1

// Pin the compiler toolchain explicitly so setup-go and local builds
// use a stdlib free of the GO-2025 vulnerabilities flagged by govulncheck:
//   - GO-2025-3956 / CVE-2025-58189 (crypto/tls KeyUpdate DoS)
//   - GO-2025-3957 / CVE-2025-58186 (crypto/x509 unexpected panic)
//   - GO-2025-3955 / CVE-2025-58188 (crypto/x509 NotAfter time DoS)
// All three are fixed in 1.26.2. The `go 1.26.1` line above is the
// language-version floor; `toolchain` pins the actual compiler.
toolchain go1.26.4

require (
	github.com/ProtonMail/gluon v0.17.1-0.20260225115619-c0f05c033a4a
	github.com/ProtonMail/go-proton-api v0.4.1-0.20260424150947-6bf7f5a61eb8
	github.com/ProtonMail/gopenpgp/v2 v2.10.0-proton
	github.com/charmbracelet/bubbles v1.0.0
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/charmbracelet/log v1.0.0
	github.com/google/uuid v1.6.0
	github.com/jmoiron/sqlx v1.4.0
	github.com/modelcontextprotocol/go-sdk v1.6.1
	github.com/pressly/goose/v3 v3.27.1
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/net v0.53.0
	golang.org/x/term v0.44.0
	modernc.org/sqlite v1.50.0
)

require (
	github.com/ProtonMail/bcrypt v0.0.0-20211005172633-e235017c1baf // indirect
	github.com/ProtonMail/go-crypto v1.4.1-proton // indirect
	github.com/ProtonMail/go-mime v0.0.0-20230322103455-7d82a3887f2f // indirect
	github.com/ProtonMail/go-srp v0.0.7 // indirect
	github.com/PuerkitoBio/goquery v1.12.0 // indirect
	github.com/andybalholm/cascadia v1.3.3 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/bradenaw/juniper v0.15.3 // indirect
	github.com/charmbracelet/colorprofile v0.4.1 // indirect
	github.com/charmbracelet/harmonica v0.2.0 // indirect
	github.com/charmbracelet/x/ansi v0.11.6 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.9.0 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.5.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/cronokirby/saferith v0.33.0 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emersion/go-message v0.16.0 // indirect
	github.com/emersion/go-textwrapper v0.0.0-20200911093747-65d896831594 // indirect
	github.com/emersion/go-vcard v0.0.0-20230331202150-f3d26859ccd3 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/go-logfmt/logfmt v0.6.1 // indirect
	github.com/go-resty/resty/v2 v2.17.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/sethvargo/go-retry v0.3.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	gitlab.com/c0b/go-ordered-json v0.0.0-20201030195603-febf46534d5a // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	modernc.org/libc v1.72.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/go-resty/resty/v2 => github.com/ProtonMail/resty/v2 v2.0.0-20250929142426-e3dc6308c80b
