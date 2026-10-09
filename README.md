# Realme Pad Mini RMP2106 — stock firmware inspector

An experimental, **read-only** GitHub Actions workflow for Realme Pad Mini (RMP2106, RMP2106PU_11.A.21).

## Run
1. Open **Actions → Inspect RMP2106 super.img → Run workflow**.
2. The runner uses `gdown` to fetch the previously supplied Google Drive file ID `1LVuewT3smLf-F-qWvzGm21Rk_z-p6Got`. It must be accessible to `gdown`.
3. Optionally supply the expected SHA-256 to detect incomplete or altered downloads.
4. Download the `inspection-report` artifact: `partitions.json`, `lpdump.txt`, and `apps.csv`.

This pipeline handles sparse/raw super images, unpacks partitions using `lpunpack`, recognizes EXT-family filesystem images and scans common APK directories with read-only `debugfs`. It does **not** debloat, repack, flash, modify AVB, or run on your tablet. Keep the original PAC/firmware backup.

**Not yet tested against the actual device firmware or a GitHub Actions run.** The binary partition-tool source is currently an unpinned third-party dependency; review/pin it before relying on outputs. Ensure repository Actions are enabled. GitHub-hosted runner disk space may be insufficient for very large super images.


## Full recursive APK scan (Phase 1B)

Open **Actions → Scan all EXT APK directories → Run workflow**. This second workflow downloads the same Google Drive `super.img` via `gdown`, checks its SHA-256 if provided, unpacks it, and traverses every directory in each EXT-family partition with read-only `debugfs`. It does not limit discovery to `app/` or `priv-app/`: this can find APKs in OEM, Realme and preload directories.

The resulting **complete-apk-inventory** artifact contains:

- `all-apks.csv` — every APK path discovered by the scan
- `debloat-candidates.csv` — keyword matches for Assistant, Facebook, Books, Kids, Google One, Google Pay, music, and other requested applications
- `scan-statistics.json` — directories inspected and truncation/error flags

**IMPORTANT:** Keyword matches are potential candidates, not verified package IDs. Do not automatically delete these paths. The report may include critical system services. An incomplete scan is reported as such. This workflow does **not** modify or repack firmware, perform AVB changes or flash the device.

## Exact-path debloat plan (Phase 2: DRY RUN ONLY)

The **Scan all EXT APK directories** workflow now also reads `config/rmp2106-debloat.json` and runs `scripts/plan_debloat.py` against `all-apks.csv`.

- The manifest includes **22 exact app-directory candidates** verified against the prior 256-APK inventory. These include Google Assistant, Chrome, Gmail, Maps, YouTube, Google Books, Kids' video/music preloads, Google Pay/One, and Realme Facebook preloads.
- `review_only` keeps KidsHome, Bluetooth MIDI, BookmarkProvider, TrichromeLibrary and selected integrated services out of automatic targeting.
- The artifact now also includes `debloat-plan.csv` and `debloat-plan.json`. If a target is missing, validation fails and the artifact is still uploaded to help diagnose it.
- The planner does not edit images, delete files or generate any flashable package. Each directory must be reviewed for package dependencies, AVB constraints and filesystem security metadata before implementing modification.

The current configuration applies **only** to the RMP2106PU_11.A.21 firmware image used to create the prior inventory. Run the updated workflow on **main** to generate a fresh plan.
