"""Stand-in for the JADX CLI used by the server tests.

Behaviour is selected with FAKE_JADX_MODE:
  ok            write a manifest + one source file, exit 0
  fail          print an error to stderr, exit 1
  partial       write a manifest, exit 1 (JADX's "finished with errors")
  sleep         spawn a grandchild, record its PID in FAKE_JADX_PIDFILE, then hang
  partial_sleep like sleep, but write a manifest first
"""

import os
import subprocess
import sys
import time
from pathlib import Path

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.fake"
    android:versionCode="7" android:versionName="1.7">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.SEND_SMS"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application>
    <activity android:name=".MainActivity"/>
    <service android:name=".SyncService"/>
  </application>
</manifest>
"""

SOURCE = """package com.example.fake;
class Loader {
  void run() throws Exception {
    new dalvik.system.DexClassLoader(null, null, null, null);
    Runtime.getRuntime().exec("id");
    String c2 = "https://c2.example.test/beacon";
  }
}
"""


def main() -> int:
    args = sys.argv[1:]
    out = Path(args[args.index("-d") + 1])
    mode = os.environ.get("FAKE_JADX_MODE", "ok")

    def write_manifest() -> None:
        (out / "resources").mkdir(parents=True, exist_ok=True)
        (out / "resources" / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")

    for pct in (0, 50, 100):
        print(f"INFO  - progress: {pct} of 100 ({pct}%)", flush=True)

    if mode == "ok":
        write_manifest()
        src = out / "sources" / "com" / "example" / "fake"
        src.mkdir(parents=True, exist_ok=True)
        (src / "Loader.java").write_text(SOURCE, encoding="utf-8")
        return 0
    if mode == "fail":
        print("ERROR - jadx: input file is corrupt", file=sys.stderr, flush=True)
        return 1
    if mode == "partial":
        write_manifest()
        print("ERROR - finished with errors, count: 3", file=sys.stderr, flush=True)
        return 1
    if mode in ("sleep", "partial_sleep"):
        if mode == "partial_sleep":
            write_manifest()
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        pidfile = os.environ.get("FAKE_JADX_PIDFILE")
        if pidfile:
            Path(pidfile).write_text(str(child.pid), encoding="utf-8")
        time.sleep(120)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
