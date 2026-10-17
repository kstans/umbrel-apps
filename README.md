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
