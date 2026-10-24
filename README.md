# kstans Umbrel community app store

Add `https://github.com/kstans/umbrel-apps` under App Store → Community App Stores in umbrelOS.

## Apps

- **kstans-foundryvtt** — Foundry VTT 14.360 (`felddy/foundryvtt`) on host port 30000. Holds no
  data itself: set a custom mount `/External/HPdrive/foundry-vtt` → `/data` on the `server`
  service before first use. Contains no license or credentials.
- **kstans-wyze-bridge** — Wyze Bridge 4.5.0 (`idisposablegithub365/wyze-bridge`), host-networked:
  WebUI :5080, RTSP :8554, HLS :8888, WebRTC :8889 / :8189udp. Set `WYZE_EMAIL`, `WYZE_PASSWORD`,
  `WYZE_API_ID`, `WYZE_API_KEY` as custom environment on the `server` service before first use.
  Contains no credentials.
- **kstans-pc-reports** — PC Reports 1.1.0: every SimpleHelp machine by group, with a report page
  per PC, rescan buttons (they run only the read-only toolbox tool `pc-report`), "Mark OK" for
  warnings, filter cards and PDFs per PC, subgroup and group. Every 15 minutes it re-reads the
  machine list and scans online PCs that have never been scanned (each at most once a day). Runs the image `ghcr.io/kstans/pc-reports` (built from `app/` by GitHub Actions), host-networked on :8765, behind a password. To release: bump `version` in `umbrel-app.yml` with the code change and push; when the "PC Reports image" build finishes, pin the new tag and digest in `docker-compose.yml` and push again.
  Set `PC_REPORTS_PASSWORD`, `SIMPLEHELP_URL`, `SIMPLEHELP_TOKEN`, `SIMPLEHELP_TECHNICIAN` and
  `SIMPLEHELP_CONNECT_ADDRESS` as custom environment on the `server` service before first use.
  HTTPS on the tailnet: run `pc-reports-https.sh` (Tailscale Serve, :8444 → 8765) once on the Umbrel.
  Contains no credentials.
