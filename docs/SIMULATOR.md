# TAK Simulator

The TAK Simulator streams scripted, synthetic Cursor on Target (CoT) into your TAK Server so
anyone watching in ATAK, iTAK, WinTAK, WebTAK, CloudTAK or TAK Portal sees a live exercise, a
technology demonstration, or a load test. Nothing changes on the clients, and nothing reaches a
user who did not opt in.

It needs **CloudTAK on the same box**: the marketplace card stays greyed out, and a deploy is
refused, until CloudTAK is deployed. That is a dependency, not an update-channel restriction —
every channel offers it. Once the Simulator is installed its log, controls and removal stay
reachable even if CloudTAK is later removed.

## What it is for

- **Technology demonstrations.** A healthy box with an empty map shows nothing. The showcase
  preset puts engines, a helicopter, a drone with a sensor cone and a video link, fixed cameras,
  chat, a CASEVAC, a hostile marker and a published route on the map in one picture.
- **Training and exercises.** Instructors inject a moving picture, timed events (a CASEVAC at
  t+5, an emergency beacon at t+12) and tempo changes into a class of real clients.
- **Load and validation.** Hundreds to thousands of synthetic units reporting every few seconds,
  with a rate governor, for sizing and for validating Guard Dog's CoT-database monitors.

## Isolation: the channel is the switch

TAK Server delivers a connection's traffic to everyone who shares its active groups (channels).
The simulator sends on **lanes**: each lane is its own service identity in Authentik
(`sim-lane-1`, `sim-lane-2`, ...) with its own enrolled certificate and its own connection, and
each lane is a member of **exactly one** channel. Choosing a channel for a lane sets that
membership. That is the whole delivery model, and it is why a dispatcher who never joined the
channel never sees a simulated beacon.

- Deploying creates the channel **`simulation`** (Authentik group `tak_simulation`). It is the
  default and the safe place to run anything.
- To watch: in TAK Portal add the viewers to the `simulation` channel; in ATAK open **Channels**
  and toggle `simulation` on to see the exercise and off to get the real picture back.
- Running on a **real** channel is allowed for exercises that need the live picture. The page asks
  you to type the channel name back, every callsign is prefixed `EX-`, and every object carries
  `EXERCISE EXERCISE EXERCISE` in its remarks (it carries that remark on the simulation channel too).
- **Stop is clean.** On Stop, on a natural end, and when the container is stopped, the engine sends
  a delete for every object it ever emitted and closes the lanes. Objects also carry a short
  stale time (60 s by default), so even a crash clears the clients within a minute.

## Deploying

Marketplace → **TAK Simulator** → Deploy. Pre-flight checks that CloudTAK is deployed on this box
(the card reads *Requires CloudTAK — deploy CloudTAK first, then return here* until it is), that
TAK Server is installed, that Authentik is installed (the lane identities are LDAP users), that
ports 8089 and 8446 answer locally, and that Docker is present. The deploy then:

1. creates the `tak_simulation` group,
2. creates the `sim-lane-1` service account and enrolls a certificate for it over TAK's own
   certificate-enrollment API (the one-time password is discarded; the certificate is the
   credential),
3. builds and starts the `tak-simulator` container.

The container is plain Python 3.12 from a digest-pinned image with no third-party packages,
runs as an unprivileged user with a read-only root filesystem and no capabilities, has no
host networking, no Docker socket, and no public port. Its control API listens on
`127.0.0.1:5090` only, behind a bearer token the console generates at deploy, and — when CloudTAK
is on the same box — on the private `infratak` Docker network so the CloudTAK panel below can
drive it. Outbound it reaches only TAK Server (8089, and 8443 to switch its own channels on).

## Running a scenario

1. Pick a scenario card.
2. Choose an **area of operations** (a city from the list, or type a center latitude/longitude).
   Every preset is built from offsets around that center, so it runs anywhere.
3. Assign each lane the scenario uses to a channel. `simulation` is preselected.
4. Pick a tempo (1×, 2×, 4×, 10×). Tempo scales both movement and the event timeline.
5. Start. Pause/Resume freeze and release the simulated clock; Stop sends the deletes.

The **Live** card shows the simulated clock, entities alive, events fired, and per-lane link state
and message rate. The engine log is the container's log.

### Presets

| preset | story | shows off |
|---|---|---|
| `demo-showcase` | 15-minute loop: engines, a helicopter, a drone with video and a sensor cone, two fixed cameras, a mesh node, a patrol car, chat, a CASEVAC at t+5, a hostile marker at t+8, a route | the technology demo |
| `wildfire-ia` | initial attack: crews on the perimeter, engines on roads, air attack orbiting, retardant drops, division chat | ICS-style training |
| `wilderness-sar` | four teams on assigned segments, K9, a drone sweep, a find, a CASEVAC | SAR training |
| `le-perimeter` | patrol units converging, a perimeter, a suspect track, a 911 beacon and its cancel | LE training (keep it on `simulation`) |
| `disaster-eoc` | dozens of assets across a wide area, slow tempo, periodic status chat | EOC common operating picture on a wall |
| `drone-patrol` | one UAS on a racetrack with a sensor cone and a video link | the MediaMTX → ATAK/CloudTAK video path |
| `load-test` | N units (50–2000, a run parameter) on random walks with short stale | T&E, Guard Dog CoT-database validation |
| `sensor-showcase` | a sweeping radar at the center, three ADS-B-shaped aircraft, two AIS-shaped vessels, a helicopter hold, a UAS with sensor and video, four ground units on a patrol route, 20-minute loop at 2× | the sensor picture: radar cone, air, sea |

Video links point at the box's MediaMTX or TAK Video Restreamer (`rtsp://<host>:8554/<stream>`)
when one is installed; publish a stream under the name the entity uses (`uas1` in the showcase and
drone presets) and the video button in ATAK/CloudTAK opens it. Without a media server the link is
simply omitted.

## Writing a scenario

A scenario is a JSON document. Upload it from the Run card (1 MB cap). It is validated strictly:
unknown keys are rejected everywhere, strings and numbers are capped, and nothing in the file is
a path or code. Coordinates are `[east_m, north_m]` offsets from the run's center.

```json
{
  "title": "My exercise",
  "story": "One line shown on the card.",
  "duration_s": 900,
  "loop": true,
  "default_tempo": 2,
  "warn": "Optional text shown before Start.",
  "defaults": {"interval_s": 5, "stale_s": 60, "team": "Cyan", "role": "Team Member", "lane": "1"},
  "areas": {"search": [[-500, -500], [500, -500], [500, 500], [-500, 500]]},
  "entities": [
    {"id": "e1", "callsign": "ENGINE 1", "type": "a-f-G-E-V-C", "team": "Red", "role": "Team Lead",
     "path": {"kind": "waypoints", "speed_mps": 12, "loop": true, "pause_s": 20, "points": [[-2000, -1000], [0, 0], [500, 300]]}},
    {"id": "t1", "callsign": "TEAM 1", "type": "a-f-G-U-C",
     "path": {"kind": "random_walk", "area": "search", "speed_mps": 1.2, "turn_deg_s": 30}},
    {"id": "air", "callsign": "AIR 1", "type": "a-f-A-M-H", "hae_m": 400, "interval_s": 2, "spawn_at_s": 120,
     "path": {"kind": "orbit", "center": [0, 0], "radius_m": 1000, "speed_mps": 45, "clockwise": true}},
    {"id": "uas", "callsign": "UAS 1", "type": "a-f-A-M-H-Q", "hae_m": 120,
     "sensor": {"fov": 45, "range_m": 600, "vfov": 30, "elevation": -30}, "video": {"stream": "uas1"},
     "path": {"kind": "waypoints", "speed_mps": 12, "points": [[-400, 200], [400, 200], [400, -200], [-400, -200]]}},
    {"id": "ic", "callsign": "COMMAND", "type": "a-f-G-U-C", "role": "HQ", "path": {"kind": "static", "at": [0, -300]}}
  ],
  "events": [
    {"at_s": 0,   "kind": "polygon", "id": "zone", "callsign": "HOT ZONE", "stroke": "#ff3b30", "fill": "#ff3b30", "fill_alpha": 50, "points": [[-200, -150], [200, -150], [200, 150], [-200, 150]]},
    {"at_s": 0,   "kind": "circle",  "id": "lz", "callsign": "LZ", "at": [-400, -600], "radius_m": 60},
    {"at_s": 15,  "kind": "chat",    "from": "ic", "text": "Command established.", "room": "All Chat Rooms"},
    {"at_s": 60,  "kind": "route",   "id": "r1", "callsign": "ACCESS", "color": "#34c759", "points": [[-2000, -1000], [0, 0]]},
    {"at_s": 300, "kind": "casevac", "id": "cv1", "title": "CASEVAC 1", "at": [60, 40], "urgent": 1, "litter": 1, "ambulatory": 0, "remarks": "One patient"},
    {"at_s": 480, "kind": "marker",  "id": "sus", "callsign": "SUSPECT", "type": "a-h-G", "at": [640, -120]},
    {"at_s": 600, "kind": "emergency", "from": "t1", "alert": "911 Alert"},
    {"at_s": 700, "kind": "emergency_cancel", "from": "t1"},
    {"at_s": 720, "kind": "spawn", "entity": "air"},
    {"at_s": 800, "kind": "callsign", "entity": "t1", "callsign": "TEAM 1 RELIEF"},
    {"at_s": 810, "kind": "team", "entity": "t1", "team": "Yellow", "role": "Team Lead"},
    {"at_s": 850, "kind": "remove", "id": "cv1"},
    {"at_s": 880, "kind": "despawn", "entity": "uas"}
  ]
}
```

Reference:

- **Entity** — `id` (letters, digits, `_`, `-`), `callsign`, CoT `type` (for example `a-f-G-U-C`
  friendly ground unit, `a-f-G-E-V-C` vehicle, `a-f-A-M-H` helicopter, `a-f-A-M-H-Q` rotary
  drone, `a-f-G-E-S` sensor, `a-h-G` hostile, `a-n-G` neutral), `team` (ATAK team color name),
  `role`, `lane`, `path`, `interval_s` (0.5–600), `stale_s` (5–86400), `hae_m`, `spawn_at_s`,
  `despawn_at_s`, optional `sensor` (`fov`, `range_m`, `vfov`, `elevation`, `sweep_deg_s`; azimuth
  follows heading, and a sweep advances it that many degrees per simulated second for a radar),
  optional `video` (`stream` name), optional `remarks`, plus the detection keys below (`silent`,
  `detected_type`, `detected_callsign`, `eud`).
- **Paths** — `waypoints` (`points`, `speed_mps`, `loop`, `pause_s`), `random_walk` (inside a
  named `area`, an inline `polygon`, or a `radius_m` around `start`; `speed_mps`, `turn_deg_s`),
  `orbit` (`center`, `radius_m`, `speed_mps`, `clockwise`), `static` (`at`), `heading` (`at`,
  `heading_deg`, `speed_mps` — a straight course held until something changes it, which is what
  the panel's **Set course** writes).
- **Events** — `chat`, `casevac`, `emergency` / `emergency_cancel` (`alert`: `911 Alert`, `Ring The
  Bell`, `In Contact`, `Geo-fence Breached`), `marker`, `route`, `polygon`, `circle`, `spawn`,
  `despawn`, `callsign`, `team`, `remove`. Markers, shapes, routes and CASEVACs persist (they are
  re-sent every half stale) until removed or the run stops.
- **`generate`** — for load runs: `count`, `count_min`, `count_max`, `callsign_prefix`, `type`,
  `team`, `role`, `lane`, `radius_m`, `interval_s`, `stale_s`, `speed_mps`. The page exposes
  count, interval and the per-lane rate cap as run parameters.
- **Caps** — 2500 entities, 500 events, 500 points per path or shape, 50 sensors with detection
  enabled, 500 hidden targets, 1 MB per file, offsets within ±200 km, 400 m/s, 30 km altitude, and
  a per-lane rate governor of 200 messages per second (raised per run for the load preset only).
- **`center`** — written by **Save layout**, so a saved picture reopens where it was made. Presets
  carry none; they run wherever you center them.

### Sensors that detect, and targets that hide

A sensor cone on its own is only drawn. Give it a `detect` block and it starts producing tracks:
any **hidden** entity inside the cone is reported by that sensor, and by every other sensor that
also sees it, so two radars on one contact give you two tracks.

```json
{
  "id": "radar1", "callsign": "COASTAL RADAR", "type": "a-f-G-E-S",
  "path": { "kind": "static", "at": [0, 0] },
  "sensor": {
    "fov": 360, "range_m": 40000, "vfov": 30, "elevation": 0, "sweep_deg_s": 60,
    "detect": { "kinds": ["sea", "air"], "error_m": 120, "p_detect": 0.8,
                "alt_min_m": -50, "alt_max_m": 8000 }
  }
}
```

```json
{
  "id": "contact1", "callsign": "UNKNOWN VESSEL", "type": "a-u-S-X-M",
  "silent": true, "detected_callsign": "TRACK 041",
  "path": { "kind": "waypoints", "speed_mps": 6, "loop": false,
            "points": [[-30000, 12000], [-5000, 4000], [15000, -8000]] }
}
```

- **`detect`** — `kinds` (`air`, `sea`, `ground`), `alt_min_m` / `alt_max_m` (the altitude band it
  sees), `error_m` (1-sigma position error the track is reported with), `p_detect` (0–1, the chance
  a look acquires the target), `track_stale_s` (default: twice the sensor's report interval, never
  under 10 s — a track outside the cone longer than this is dropped), and `observe` (up to 8 CoT
  type prefixes of **real** traffic on the channel that should also be reported as tracks).
- **`silent`** — the entity moves but never reports itself. It exists on the wire only as somebody's
  track. Without a sensor that sees it, it is invisible, which is the point.
- **`detected_type`** — what a sensor calls it. Defaults to the unknown atom of its domain:
  `a-u-A` air, `a-u-S` sea, `a-u-G` ground. **`detected_callsign`** names the track; without one the
  sensor names it.
- **`eud`** — whether the unit reports like a person carrying a TAK device. It defaults correctly:
  on for friendly ground personnel (`a-f-G-U…`), off for everything else. Leave it alone. A report
  that carries the team/role tag draws as the team-colored marker on every TAK client, and one
  without it draws as the MIL-STD-2525 symbol for its type — so forcing it on a ship or an aircraft
  turns your frigate into a colored dot.

## Directing it from the CloudTAK map

With CloudTAK on the same box, the Simulator page offers **Install CloudTAK panel** (it rebuilds
the CloudTAK API image, 5–10 minutes; close every CloudTAK tab afterwards, its service worker
caches the old bundle). CloudTAK then has a **TAK Simulator** tool in its menu:

- **Session** — start an empty live session at the map center, **Run at map center** with a preset,
  or **Open for editing**, which places a preset at the center as a live session you can move,
  add to, thin out and save again as a new layout. Tempo, pause, resume, and **Stop (clears
  everything)**. The panel warns when you are not in the channel the traffic goes to, because then
  you would see nothing.
- **Add unit** — pick a type (ground, vehicle, hostile, helicopter, fixed wing, UAS, ADS-B
  aircraft, vessel, AIS vessel, radar site, fixed camera), callsign, team, altitude in feet, speed
  in knots, an optional sensor cone (FOV, range, and a sweep for a radar) and video stream, then
  **Place on map** and click. Two checkboxes matter: **Hidden target** makes a unit that never
  reports itself (it appears only as the track of a sensor that sees it), and **Team marker (TAK
  user)** controls team-marker versus 2525 rendering — its default is right, see `eud` above.
- **Detects** — on a unit with a sensor cone, switch detection on and pick what it sees (air, sea,
  ground), the position error, the hit chance and the altitude band. Hidden targets crossing the
  cone become tracks named by that sensor; switching it off deletes those tracks.
- **Units** — every live unit with altitude, heading and speed. Per unit: Go To (click the map),
  Route (several clicks), Orbit here, Hold, Set course / altitude, Lost link (the unit stops
  reporting and goes stale on every client, it is not deleted), chat, 911 and its cancel, a
  CASEVAC at its position, Remove.
- **Shapes & markers** — marker, CASEVAC, circle, polygon and route by map clicks (Enter or Esc
  finishes a polygon or route).
- **Save layout** — writes the current picture as an uploaded scenario, which appears in the preset
  list here and on the console page. It records the map center it was built at, so it reopens in
  place. The file it writes is ordinary scenario JSON: pull it off the box and hand-tune it if you
  want it exact. **Building the first version on the map and then editing the JSON is the fastest
  way to author a scenario, and the document is valid by construction.**

Nothing is sent from the browser. Every action goes to the engine on the box, which sends on
its enrolled lane exactly as a scripted run does: the same channel isolation, the same
`EXERCISE` marking, the same delete-on-stop. A lane keeps the channel the console enrolled it on
— a request cannot relabel it — and a real channel still needs its name typed back, in the panel
as on this page. Any signed-in CloudTAK user can direct; making it admin-only is a one-line
switch in the server route (`DIRECTOR_ADMIN_ONLY`).

The same commands are available to anything else on the box through the control API (`POST
/live`, `POST /cmd`, `GET /state`, `POST /save` on `127.0.0.1:5090` with the bearer token from
`settings.json`), which is what the panel's server route uses.

## Multiple channels

A scenario may put entities on several lanes (`"lane": "2"`). Each lane is assigned its own channel
on the Run card; a lane identity is created and enrolled the first time it is used. This is how a
red-cell picture goes to one channel and the blue picture to another.

## Removing

The Remove button stops any run (deletes go out), removes the container and image, deletes the
`sim-lane-*` identities from Authentik, and removes `~/tak-simulator` (including uploaded
scenarios). The `simulation` channel is kept by default, because viewer memberships belong to the
viewers; tick the box to remove it too.

## Guard Dog

Guard Dog watches the `tak-simulator` container (liveness only). A scenario that is not running is
normal and never alerts; only a dead container does.
