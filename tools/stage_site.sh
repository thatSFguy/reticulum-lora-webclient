#!/usr/bin/env bash
# Copy only the files the Android WebView needs into www/, which is
# what capacitor.config.json points at as the webDir. Called by the
# bootstrap and build-apk workflows before every `cap sync android`,
# and by `npm run stage` for local smoke tests.
#
# Kept parallel to the Stage static site step in .github/workflows/
# deploy.yml so the APK and the Pages deploy always ship the same
# set of files. If you add a new static asset directory, add it to
# both places.

set -euo pipefail

rm -rf www
mkdir -p www
cp index.html www/
cp -r css js www/
# .nojekyll is a no-op inside the WebView but keeping it means the
# www/ layout is a bit-for-bit mirror of what Pages serves.
touch www/.nojekyll

echo "Staged $(find www -type f | wc -l) files into www/"
