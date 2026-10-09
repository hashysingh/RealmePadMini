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


## Experimental offline debloat build (Phase 3)

**Warning: this is an untested experimental builder. It does NOT produce a flash-validated image. Do not flash it to the tablet until AVB, bootloader, filesystem integrity and device recovery are assessed.**

Choose **Actions → Build debloated super.img (EXPERIMENTAL) → Run workflow**, select `main` and enter `EXPERIMENTAL`. The workflow downloads the known firmware with `gdown`, checks its previously observed SHA-256, converts sparse to raw, extracts only the changed `system_a` and `product_a` partitions, and attempts to remove exactly 22 selected app directories using offline `debugfs`. It checks the modified EXT filesystems using `e2fsck -fn`. If a check fails, it stops and saves diagnostics.

Rather than recreating potentially fragile logical partition metadata with guessed `lpmake` arguments, the builder writes each updated filesystem over **the same one-extent byte range inside the original raw super image**, confirming that `lpdumps` metadata is identical before and after. It then converts raw to an Android sparse image and, on success, uploads an artifact `RMP2106-experimental-debloated-super` containing the new `super_debloated_sparse.img`, SHA-256 and diagnostics. Empty B partitions and unmodified system_ext/vendor data are not touched.

The build has **not** yet been executed against your firmware. Its static external tool dependency should be pinned and audited before distributing any ROM images. Repository Actions storage limits and runner disk constraints may affect the build. The build intentionally does not bypass AVB or handle flashing.


### One-shot build and offline verification

The **Build and offline-validate debloated super.img** workflow now runs the build and independent validation in one GitHub Actions job. During the build, it hashes *every raw super-image byte outside the two approved writable extents* (`system_a` and `product_a`) before and after editing, and fails if **any** byte differs. This covers `_b` slot data, `vendor_a`, `system_ext_a`, metadata and any unused super-image space. It also fails if the raw image size or LP metadata changes. After sparse repacking, it unsparses and re-extracts the result, runs read-only `e2fsck -fn` checks on populated EXT partitions, and verifies all 22 targeted directories are absent. Successful runs upload the final image **and** reports together. A successful offline validation is not a guarantee that device boot will work.

The user has reported an existing patched `tos-sign.img` made with `spd_dump_it dis_avb`. This repository neither patches nor verifies the device's TOS, and **does not** bypass, disable or alter AVB. Do not treat the generated image as confirmed flash-compatible without device-specific review.


### Removal-proof build (updated)

Run **Build and prove debloated super.img** on branch `main`, entering `EXPERIMENTAL`. The resulting artifact includes `removal-proof.csv` (each targeted directory verified absent after sparse repacking and fresh extraction), `remaining-apks.csv` (full APK inventory of all populated EXT partitions), and `apk-scan-statistics.json` (scan coverage/error counts), alongside the image and previous checks. The workflow **fails rather than publishes an image** if any target directory still exists, a targeted APK filename remains elsewhere, or full-partition APK traversal is incomplete.

**Scope:** This confirms contents of `super.img` only. It cannot confirm Android's `/data/app` installations, apps provisioned after boot, what partition is actually mounted on your device, or whether a flashing tool wrote the new image. Seeing an app after flashing does not by itself establish that the system-image removal failed. Check its on-device package source before flashing repeatedly.


### Optional Google Drive delivery (instead of relying only on a huge Actions ZIP)

The successful one-shot workflow still uploads its standard GitHub artifact. It can additionally upload the **finished sparse image** directly into **your own Google Drive**, provided you configure a private rclone connection. Drive upload runs **after** the standard artifact step, and an upload failure does not delete or invalidate that artifact. **No Google Drive account is connected automatically**, and no upload occurs until you configure both settings below.

1. Install [rclone](https://rclone.org/downloads/) on your own PC, run `rclone config`, and create a Google Drive remote named `gdrive` with access to your account. Follow [rclone's Google Drive instructions](https://rclone.org/drive/), including creating your own OAuth client ID; the default shared rclone client is being retired in 2026. Test that `rclone lsd gdrive:` works on your PC.
2. Base64-encode the **complete contents** of your rclone configuration file as one line. On Windows PowerShell, after finding the file with `rclone config file`, use `[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\\path\\to\\rclone.conf"))`. Treat the encoded value as a **secret**—it contains private authorization tokens. Never post it in an issue, chat, commit, or artifact.
3. In GitHub, open **Settings → Secrets and variables → Actions** for this repository. Add **repository secret** `RCLONE_CONFIG_B64` with that base64 string; add **repository variable** `DRIVE_DESTINATION` with value `gdrive:RealmePadMini` (or another folder inside the configured remote).
4. Run **Build and prove debloated super.img** normally. On success it will additionally upload `RMP2106-debloated-super-<run-id>.img` to the destination folder and compare the remote file size. It will remain **private unless you choose to share it** in Google Drive; the workflow does not expose or create public links.

Note: Changing the hosting service is not guaranteed to improve throughput; Google Drive speed depends on your account, region, and network. The existing GitHub Actions artifact remains available for three days.


**No rebuild needed for the validated October 9 result:** Once the two GitHub settings above exist, open [Transfer existing debloated super image to Google Drive](https://github.com/hashysingh/RealmePadMini/actions/workflows/transfer-debloated-super-to-drive.yml), select `main`, leave the source run ID `37954304818` and pre-filled SHA256 intact, and run it. This pulls the original GitHub Actions artifact, verifies the exact sparse image checksum **before** copying it to Drive, and confirms the remote byte count. The source artifact expires October 12, 2026; transfer it before then. Google Drive may still download slowly depending on network conditions.
