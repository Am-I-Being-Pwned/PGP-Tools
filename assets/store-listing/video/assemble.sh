#!/bin/bash
# Build the promo: the old-style film (promo.html) with a short clip of the
# real extension (film/, the three.js cut) in the middle. 720p by default.
#
#   ./assemble.sh            # out/pgp-tools-promo-1280x720.mp4
#   SCALE=2 ./assemble.sh    # out/pgp-tools-promo-3840x2160.mp4 (4K, when asked for)
#
# Segments (promo.html seconds unless noted):
#   A   0 → 5.15       pixel-art intro: the face wall, then Alice's face alone, captioned
#   B   film 0 → 11.0  the real Chrome window, side panel opening, encrypt take
#   C1a 19.55 → 22.45  real armored message, sealed for Alice (then held 0.5s)
#   C1b 22.45 → 41.86  decrypt, bad signature, Touch ID, at rest
#   C2  47.0 → 53.06   features with the Keys view
#   D   58.25 → 64     lockup
# (promo.html's logo flip and headline are cut: the intro ends on Alice's face
# and goes straight to the real window; the name and line land on the end
# card. 7.3-19.5 is its own screenshot walkthrough, replaced by B;
# 41.9-47 is the rapid-fire section and 53.1-58.2 the black-box section, both
# cut.) `--query cut` stretches the intro by 2s to say what the faces are, and
# keeps the old walkthrough out of frame. Joins dip briefly through black.
set -euo pipefail
cd "$(dirname "$0")"
SCALE=${SCALE:-0.6667}
W=$(printf "%.0f" "$(echo "1920*$SCALE" | bc)"); H=$(printf "%.0f" "$(echo "1080*$SCALE" | bc)")
OUTNAME="pgp-tools-promo-${W}x${H}.mp4"
node render.mjs --scale $SCALE --query cut --from 0 --to 5.15 --out seg-a-intro.mp4
(cd film && node render.mjs --scale $SCALE --from 0 --to 11.0 --query clip --out seg-b-clip.mp4)
node render.mjs --scale $SCALE --query cut --from 19.55 --to 22.45 --out seg-c1a.mp4
node render.mjs --scale $SCALE --query cut --from 22.45 --to 41.86 --out seg-c1b.mp4
node render.mjs --scale $SCALE --query cut --from 47.0 --to 53.06 --out seg-c2.mp4
node render.mjs --scale $SCALE --query cut --from 58.25 --to 64 --out seg-d-end.mp4

cd out
dur() { ffprobe -v error -show_entries format=duration -of csv=p=0 "$1"; }
norm="fps=60,format=yuv420p,settb=AVTB"
# C1: the sealed-message frame holds 0.5s once its lock has closed.
ffmpeg -y -loglevel error -i seg-c1a.mp4 -i seg-c1b.mp4 -filter_complex \
  "[0]$norm,tpad=stop_mode=clone:stop_duration=0.5[a];[1]$norm[b];[a][b]concat=n=2:v=1[v]" \
  -map "[v]" -c:v libx264 -preset slow -crf 14 -pix_fmt yuv420p -f mp4 seg-c1.mp4

# Join everything with short dips through black.
SEGS=(seg-a-intro.mp4 seg-b-clip.mp4 seg-c1.mp4 seg-c2.mp4 seg-d-end.mp4)
X=0.6
inputs=(); graph=""; prev="v0"; offset=0
for i in "${!SEGS[@]}"; do
  inputs+=(-i "${SEGS[$i]}")
  graph+="[$i]$norm[v$i];"
done
for ((i = 1; i < ${#SEGS[@]}; i++)); do
  offset=$(echo "$offset + $(dur "${SEGS[$((i - 1))]}") - $X" | bc)
  graph+="[$prev][v$i]xfade=transition=fadeblack:duration=$X:offset=$offset[x$i];"
  prev="x$i"
done
ffmpeg -y -loglevel error "${inputs[@]}" -filter_complex "${graph%;}" -map "[$prev]" \
  -c:v libx264 -preset slow -crf 16 -pix_fmt yuv420p -movflags +faststart -f mp4 "$OUTNAME.part"
mv "$OUTNAME.part" "$OUTNAME"
echo "wrote out/$OUTNAME ($(dur "$OUTNAME")s)"
