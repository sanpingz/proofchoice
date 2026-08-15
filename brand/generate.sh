#!/usr/bin/env bash
# Regenerate the icon set in public/ from the master artwork.
#
#     npm run icons
#
# Requires ImageMagick (brew install imagemagick). It is a one-off
# asset tool, not a runtime dependency — the generated PNGs are what
# ship, and the server needs nothing to serve them.
#
# Sizes are deliberate:
#   16/32     browser tab; 32 is what most displays actually use
#   48        inside favicon.ico, for legacy Windows contexts
#   96        the masthead mark, which renders at 26px (3x headroom)
#   180       apple-touch-icon, FLATTENED onto the navy — iOS applies
#             its own squircle mask, so transparent rounded corners
#             would mask to pale slivers
#   192/512   web manifest
#
# The large icons are reduced to a 256-colour palette. On this
# artwork that measures ~0.6% RMSE — imperceptible — and cuts the
# set from roughly 400K to 128K.

set -euo pipefail
cd "$(dirname "$0")/.."

SRC="brand/proofchoice-master.png"
OUT="public"
NAVY="#001758"

command -v magick >/dev/null || { echo "ImageMagick not found: brew install imagemagick"; exit 1; }
[ -f "$SRC" ] || { echo "missing $SRC"; exit 1; }

r() { magick "$SRC" -filter Lanczos -resize "$1x$1" -strip -define png:compression-level=9 "$OUT/$2"; }

r 512 icon-512.png
r 192 icon-192.png
r 96  logo.png
r 32  favicon-32.png
r 16  favicon-16.png

magick "$SRC" -filter Lanczos -resize 180x180 -background "$NAVY" -alpha remove -alpha off \
  -strip -define png:compression-level=9 "$OUT/apple-touch-icon.png"

magick "$SRC" -filter Lanczos -define icon:auto-resize=48,32,16 "$OUT/favicon.ico"

# Palette-reduce the large ones only; 16/32 are already tiny.
for f in icon-512 icon-192 apple-touch-icon; do
  magick "$OUT/$f.png" -strip -colors 256 -define png:compression-level=9 "$OUT/$f.png"
done

echo "Regenerated into $OUT/:"
ls -la "$OUT"/*.png "$OUT"/*.ico | awk '{printf "  %-24s %8s\n", $9, $5}'
