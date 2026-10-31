import subprocess
import os

FFMPEG = r"C:\Users\harki\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg.Essentials_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-9.0.1-essentials_build\bin\ffmpeg.exe"
MUSIC = r"C:\Users\harki\AppData\Local\Temp\brag-repo\skills\brag\assets\music\happy-beats-business-moves-vol-11-by-ende-dot-app.mp3"
CLICK1 = r"C:\Users\harki\AppData\Local\Temp\brag-repo\skills\brag\assets\sfx\interface\click_002.ogg"
CLICK2 = r"C:\Users\harki\AppData\Local\Temp\brag-repo\skills\brag\assets\sfx\ui\click2.ogg"
BONG = r"C:\Users\harki\AppData\Local\Temp\brag-repo\skills\brag\assets\sfx\interface\bong_001.ogg"
OUTPUT = r"brag-output\work\audio_mix.aac"

# Mix with exact timestamps using amix / adelay
filter_complex = (
    "[0:a]atrim=0:21,afade=t=in:ss=0:d=0.5,afade=t=out:st=19.5:d=1.5,volume=0.85[m0];"
    "[1:a]adelay=4200|4200,volume=0.8[s1];"
    "[2:a]adelay=9000|9000,volume=0.8[s2];"
    "[3:a]adelay=11200|11200,volume=1.2[s3];"
    "[4:a]adelay=14500|14500,volume=0.8[s4];"
    "[5:a]adelay=18000|18000,volume=0.8[s5];"
    "[m0][s1][s2][s3][s4][s5]amix=inputs=6:duration=first:dropout_transition=2[outa]"
)

cmd = [
    FFMPEG, "-y",
    "-i", MUSIC,
    "-i", CLICK1,
    "-i", CLICK2,
    "-i", BONG,
    "-i", CLICK2,
    "-i", CLICK1,
    "-filter_complex", filter_complex,
    "-map", "[outa]",
    "-c:a", "aac",
    "-b:a", "192k",
    "-t", "21",
    OUTPUT
]

print("Running FFmpeg audio mix...")
res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode == 0:
    print("SUCCESS: Audio mix generated at", OUTPUT)
else:
    print("ERROR:", res.stderr)

