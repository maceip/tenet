# Release bump log

Vanity commits here trigger tagged GitHub releases with three desktop binaries
(`tenet-macos-arm64`, `tenet-linux-x86_64`, `tenet-windows-x86_64.exe`).

After a release succeeds, refresh the marketing site:

```bash
./scripts/sync-www-binaries.sh          # copies into ~/tenet-www/public/downloads
cd ~/tenet-www && npm run build         # then deploy dist/ to public.computer/tenet/
```

- alpha (v0.1.1)
- beta (v0.1.2)
- gamma (v0.1.3)
