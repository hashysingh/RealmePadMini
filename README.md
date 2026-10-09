# Realme Pad Mini RMP2106 — stock firmware inspector

An experimental, **read-only** GitHub Actions workflow for Realme Pad Mini (RMP2106, RMP2106PU_11.A.21).

## Run
1. Open **Actions → Inspect RMP2106 super.img → Run workflow**.
2. The runner uses `gdown` to fetch the previously supplied Google Drive file ID `1LVuewT3smLf-F-qWvzGm21Rk_z-p6Got`. It must be accessible to `gdown`.
3. Optionally supply the expected SHA-256 to detect incomplete or altered downloads.
4. Download the `inspection-report` artifact: `partitions.json`, `lpdump.txt`, and `apps.csv`.

This pipeline handles sparse/raw super images, unpacks partitions using `lpunpack`, recognizes EXT-family filesystem images and scans common APK directories with read-only `debugfs`. It does **not** debloat, repack, flash, modify AVB, or run on your tablet. Keep the original PAC/firmware backup.

**Not yet tested against the actual device firmware or a GitHub Actions run.** The binary partition-tool source is currently an unpinned third-party dependency; review/pin it before relying on outputs. Ensure repository Actions are enabled. GitHub-hosted runner disk space may be insufficient for very large super images.
