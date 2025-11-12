[README.md](https://github.com/user-attachments/files/23510912/README.md)
# PLSChat Web Flasher (GitHub Pages)

This repo hosts a simple landing page and a browser firmware flasher powered by **ESP Web Tools**.

## Structure
```
/
  index.html           <- Landing page
  /flasher/
    index.html         <- Web flasher UI
    manifest.json      <- Maps binary files to flash offsets
    app.bin            <- Your firmware (rename from firmware.bin)
    bootloader.bin     <- Bootloader
    partitions.bin     <- Partition table
```

## How to use
1. Build your firmware (Arduino: *Sketch → Export compiled Binary*; PlatformIO: build).  
2. Copy the three binaries into `/flasher/` as:
   - `bootloader.bin`  (offset `0x0000`)
   - `partitions.bin`  (offset `0x8000`)
   - `app.bin`         (offset `0x10000`)
3. Commit & push to GitHub.
4. Enable **GitHub Pages**: Settings → Pages → "Deploy from branch" (root of `main`).
5. Visit your Pages URL and click **Install** on the flasher page.

> Requires Chrome/Edge (Web Serial). HTTPS is required for the flasher to work.
