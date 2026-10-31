import os
import sys
import math
import subprocess
from PIL import Image, ImageDraw, ImageFont

FFMPEG = r"C:\Users\harki\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg.Essentials_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-9.0.1-essentials_build\bin\ffmpeg.exe"
AUDIO_MIX = r"brag-output\work\audio_mix.aac"
OUTPUT_VIDEO = r"brag-output\brag.mp4"
POSTER_IMAGE = r"brag-output\brag.jpg"

WIDTH = 1920
HEIGHT = 1080
FPS = 30
DURATION = 21.0
TOTAL_FRAMES = int(FPS * DURATION) # 630 frames

# Color Palette (from AegisHarness Swiss Design System)
BG_PAPER = (244, 239, 230)      # #F4EFE6 warm paper
BG_IVORY = (250, 248, 245)      # #FAF8F5 ivory card
INK_BLACK = (26, 26, 26)        # #1A1A1A deep ink
INK_MUTED = (110, 107, 102)     # #6E6B66 slate stone
BORDER_RULE = (226, 221, 213)   # #E2DDD5 hairline rule
ACCENT_RED = (178, 58, 34)      # #B23A22 editorial vermillion
ACCENT_GREEN = (30, 101, 58)    # #1E653A forest sage
ACCENT_AMBER = (161, 98, 7)     # #A16207 ochre bronze
WHITE = (255, 255, 255)

# Load Fonts
FONT_SERIF_XL = ImageFont.truetype(r"C:\Windows\Fonts\georgiab.ttf", 68)
FONT_SERIF_LG = ImageFont.truetype(r"C:\Windows\Fonts\georgiab.ttf", 52)
FONT_SERIF_MD = ImageFont.truetype(r"C:\Windows\Fonts\georgia.ttf", 30)
FONT_SERIF_ITALIC = ImageFont.truetype(r"C:\Windows\Fonts\georgiai.ttf", 26)

FONT_SANS_LG = ImageFont.truetype(r"C:\Windows\Fonts\segoeuib.ttf", 28)
FONT_SANS_MD = ImageFont.truetype(r"C:\Windows\Fonts\segoeuib.ttf", 20)
FONT_SANS_SM = ImageFont.truetype(r"C:\Windows\Fonts\segoeui.ttf", 16)
FONT_SANS_CAPTION = ImageFont.truetype(r"C:\Windows\Fonts\segoeuib.ttf", 13)

FONT_MONO_LG = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 26)
FONT_MONO_MD = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 20)
FONT_MONO_SM = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 15)

# Load real vector asset illustrations
img_hacker = Image.open(r"web\images\vector_hacker_attack.png").convert("RGBA")
img_login = Image.open(r"web\images\vector_zero_trust_login.png").convert("RGBA")
img_policy = Image.open(r"web\images\vector_policy_check.png").convert("RGBA")

# Helper easing functions
def ease_out_quad(t):
    return 1 - (1 - t) * (1 - t)

def ease_in_out_quad(t):
    return 2 * t * t if t < 0.5 else 1 - math.pow(-2 * t + 2, 2) / 2

def ease_out_cubic(t):
    return 1 - math.pow(1 - t, 3)

def clamp(val, min_v=0.0, max_v=1.0):
    return max(min_v, min(val, max_v))

def draw_pill(draw, x1, y1, x2, y2, fill, outline=None, width=1):
    r = (y2 - y1) // 2
    draw.rounded_rectangle([x1, y1, x2, y2], radius=r, fill=fill, outline=outline, width=width)

def draw_badge(draw, text, x, y, bg, fg, border=None, font=FONT_SANS_CAPTION):
    bbox = font.getbbox(text)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    px, py = 12, 5
    x1, y1, x2, y2 = x, y, x + tw + px * 2, y + th + py * 2
    draw.rounded_rectangle([x1, y1, x2, y2], radius=4, fill=bg, outline=border, width=1 if border else 0)
    draw.text((x + px, y + py - 1), text, fill=fg, font=font)
    return x2

# 3D Rotating Kernel Polyhedron
def project_3d_point(x, y, z, rot_x, rot_y, cx, cy, scale=180):
    # Rotate around Y axis
    cos_y, sin_y = math.cos(rot_y), math.sin(rot_y)
    x1 = x * cos_y + z * sin_y
    z1 = -x * sin_y + z * cos_y
    
    # Rotate around X axis
    cos_x, sin_x = math.cos(rot_x), math.sin(rot_x)
    y1 = y * cos_x - z1 * sin_x
    z2 = y * sin_x + z1 * cos_x
    
    fov = 400
    p = fov / (fov + z2 + 250)
    return (cx + x1 * p * scale, cy + y1 * p * scale, z2)

KERNEL_VERTICES = [
    (-0.6, -0.6, -0.6), (0.6, -0.6, -0.6), (0.6, 0.6, -0.6), (-0.6, 0.6, -0.6),
    (-0.6, -0.6, 0.6),  (0.6, -0.6, 0.6),  (0.6, 0.6, 0.6),  (-0.6, 0.6, 0.6),
    (0, -0.95, 0),      (0, 0.95, 0),      (-0.95, 0, 0),    (0.95, 0, 0)
]

KERNEL_EDGES = [
    (0,1), (1,2), (2,3), (3,0),
    (4,5), (5,6), (6,7), (7,4),
    (0,4), (1,5), (2,6), (3,7),
    (8,0), (8,1), (8,4), (8,5),
    (9,2), (9,3), (9,6), (9,7),
    (10,0), (10,3), (10,4), (10,7),
    (11,1), (11,2), (11,5), (11,6)
]

def draw_3d_kernel(draw, cx, cy, t_sec):
    rot_y = t_sec * 0.9
    rot_x = math.sin(t_sec * 0.6) * 0.35 + 0.2
    
    projected = [project_3d_point(vx, vy, vz, rot_x, rot_y, cx, cy) for (vx, vy, vz) in KERNEL_VERTICES]
    
    # Draw edges
    for i1, i2 in KERNEL_EDGES:
        p1, p2 = projected[i1], projected[i2]
        avg_z = (p1[2] + p2[2]) / 2.0
        alpha = int(clamp((avg_z + 1.0) / 2.0, 0.3, 1.0) * 160)
        edge_col = (178, 58, 34) if i1 >= 8 or i2 >= 8 else (80, 80, 80)
        draw.line([(p1[0], p1[1]), (p2[0], p2[1])], fill=edge_col, width=2)
        
    # Draw node vertices
    for px, py, pz in projected:
        r = 5
        draw.ellipse([px - r, py - r, px + r, py + r], fill=ACCENT_RED, outline=INK_BLACK, width=1)


def render_frame(f_idx):
    t = f_idx / FPS # current time in seconds
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_PAPER)
    draw = ImageDraw.Draw(img)
    
    # Global Swiss Hairline Grid Frame
    draw.rectangle([45, 45, WIDTH - 45, HEIGHT - 45], outline=BORDER_RULE, width=1)
    
    # Common Editorial Masthead Bar
    draw.text((65, 62), "ISSUE N° 48 • AUTUMN 2026 • THE AEGIS HARNESS SPECIFICATION", fill=INK_MUTED, font=FONT_SANS_CAPTION)
    draw.text((WIDTH - 65, 62), "KOLKATA, WEST BENGAL • CCU 22°34′N 88°22′E", fill=INK_MUTED, font=FONT_SANS_CAPTION, anchor="ra")
    draw.line([(65, 88), (WIDTH - 65, 88)], fill=BORDER_RULE, width=1)
    
    # Brand in Header
    draw.text((65, 105), "Aegis", fill=INK_BLACK, font=FONT_SANS_LG)
    bbox_aegis = FONT_SANS_LG.getbbox("Aegis")
    aw = bbox_aegis[2] - bbox_aegis[0]
    draw.text((65 + aw, 105), "Harness", fill=ACCENT_RED, font=FONT_SANS_LG)
    draw.text((65 + aw + 130, 114), "• ZERO-TRUST EVALUATION & CONTAINMENT SANDBOX", fill=INK_MUTED, font=FONT_SANS_CAPTION)
    
    draw.line([(65, 145), (WIDTH - 65, 145)], fill=BORDER_RULE, width=1)

    # =========================================================================
    # SCENE 1: The Question & The Hook (0.0s – 4.2s)
    # =========================================================================
    if t < 4.4:
        s_alpha = 1.0 if t < 3.8 else clamp((4.4 - t) / 0.6)
        prog = clamp(t / 1.0)
        y_offset = (1.0 - ease_out_cubic(prog)) * 30
        
        # Center display
        cy = 440 + y_offset
        
        # Line 1: Can your AI agent be trusted?
        draw.text((WIDTH//2 - 160, cy - 80), "Can your AI agent be", fill=INK_BLACK, font=FONT_SERIF_XL, anchor="rm")
        
        # "trusted" highlight pill
        trust_x = WIDTH//2 - 140
        draw_pill(draw, trust_x, cy - 125, trust_x + 250, cy - 35, fill=(251, 235, 232), outline=ACCENT_RED, width=2)
        draw.text((trust_x + 125, cy - 80), "trusted", fill=ACCENT_RED, font=FONT_SERIF_XL, anchor="mm")
        draw.text((trust_x + 270, cy - 80), "?", fill=INK_BLACK, font=FONT_SERIF_XL, anchor="lm")
        
        # Line 2: Put it to the test.
        if t > 0.8:
            prog2 = clamp((t - 0.8) / 0.8)
            y_off2 = (1.0 - ease_out_cubic(prog2)) * 20
            draw.text((WIDTH//2, cy + 20 + y_off2), "Put it to the test.", fill=INK_BLACK, font=FONT_SERIF_XL, anchor="mm")
            
        # Line 3: Subtitle
        if t > 1.4:
            prog3 = clamp((t - 1.4) / 0.8)
            y_off3 = (1.0 - ease_out_cubic(prog3)) * 15
            draw.text((WIDTH//2, cy + 120 + y_off3), "Challenge AI agents. Expose unauthorized actions. Verify that every operation remains under control.", fill=INK_MUTED, font=FONT_SERIF_MD, anchor="mm")
            
        # Badges row
        if t > 2.0:
            bx = WIDTH//2 - 380
            by = int(cy + 220)
            bx = draw_badge(draw, "[PEP] 100% Policy Sentry", bx, by, WHITE, INK_BLACK, BORDER_RULE, FONT_SANS_MD) + 20
            bx = draw_badge(draw, "[SLA] < 15ms Slaughter", bx, by, (251, 235, 232), ACCENT_RED, (242, 195, 188), FONT_SANS_MD) + 20
            draw_badge(draw, "[WORM] SHA-256 Merkle Ledger", bx, by, (235, 245, 238), ACCENT_GREEN, (196, 226, 206), FONT_SANS_MD)

    # =========================================================================
    # SCENE 2: The Tri-Workload Architecture & 3D Kernel (4.2s – 9.0s)
    # =========================================================================
    elif t < 9.2:
        s2_t = t - 4.2
        fade_in = clamp(s2_t / 0.5)
        
        # Section Header
        draw.text((65, 165), "01 / ARCHITECTURAL SPECIFICATION • FORM FOLGT INVARIANTE", fill=ACCENT_RED, font=FONT_SANS_CAPTION)
        draw.text((65, 195), "Form folgt Invariante.", fill=INK_BLACK, font=FONT_SERIF_LG)
        draw.text((65, 242), "The Architecture of Unyielding Zero-Trust Containment.", fill=INK_MUTED, font=FONT_SERIF_ITALIC)
        
        # 3 Zone Cards layout (Left, Center 3D Kernel, Right)
        card_w, card_h = 490, 480
        top_y = 295
        
        # 1. Red Zone Card (Adversarial Testing)
        rz_x = 65
        draw.rounded_rectangle([rz_x, top_y, rz_x + card_w, top_y + card_h], radius=6, fill=WHITE, outline=BORDER_RULE, width=1)
        draw.rectangle([rz_x, top_y, rz_x + card_w, top_y + 4], fill=ACCENT_RED)
        draw_badge(draw, "RED ZONE", rz_x + 20, top_y + 18, (251, 235, 232), ACCENT_RED, (242, 195, 188), FONT_SANS_CAPTION)
        draw.text((rz_x + 20, top_y + 55), "Adversarial Ingress", fill=INK_BLACK, font=FONT_SANS_LG)
        draw.text((rz_x + 20, top_y + 95), "Simulates real-world jailbreaks, indirect prompt\ninjections, SSRF, and credential exfiltrations\ndirectly against foundation model weights.", fill=INK_MUTED, font=FONT_SANS_SM)
        # Paste thumbnail
        hacker_thumb = img_hacker.resize((360, 240))
        img.paste(hacker_thumb, (rz_x + 65, top_y + 190), hacker_thumb)
        draw.text((rz_x + 20, top_y + card_h - 35), "[MITRE ATLAS AML.T0054 & AML.T0024]", fill=ACCENT_RED, font=FONT_MONO_SM)

        # 2. Center 3D Isolation Core (Target Zone + Visual Polyhedron)
        tz_x = rz_x + card_w + 35
        draw.rounded_rectangle([tz_x, top_y, tz_x + card_w + 240, top_y + card_h], radius=6, fill=BG_IVORY, outline=BORDER_RULE, width=1)
        draw.rectangle([tz_x, top_y, tz_x + card_w + 240, top_y + 4], fill=ACCENT_AMBER)
        draw_badge(draw, "TARGET ZONE — DISPOSABLE SANDBOX", tz_x + 20, top_y + 18, (254, 249, 238), ACCENT_AMBER, (252, 232, 189), FONT_SANS_CAPTION)
        draw.text((tz_x + 20, top_y + 55), "Ephemeral VFS & Host Syscall Isolation", fill=INK_BLACK, font=FONT_SANS_LG)
        draw.text((tz_x + 20, top_y + 95), "Disposable runtime boundary strictly separating LLM proposals\nfrom host system resources. Monitored via kernel telemetry.", fill=INK_MUTED, font=FONT_SANS_SM)
        
        # Draw 3D rotating kernel in card center
        draw_3d_kernel(draw, tz_x + (card_w + 240)//2, top_y + 280, s2_t)
        draw.text((tz_x + 20, top_y + card_h - 35), "STATE: DISPOSABLE OS CONTAINER [ONLINE]", fill=ACCENT_GREEN, font=FONT_MONO_SM)

        # 3. Blue Zone Card (Policy Enforcement Point)
        bz_x = tz_x + card_w + 275
        draw.rounded_rectangle([bz_x, top_y, bz_x + card_w, top_y + card_h], radius=6, fill=WHITE, outline=BORDER_RULE, width=1)
        draw.rectangle([bz_x, top_y, bz_x + card_w, top_y + 4], fill=ACCENT_GREEN)
        draw_badge(draw, "BLUE ZONE", bz_x + 20, top_y + 18, (235, 245, 238), ACCENT_GREEN, (196, 226, 206), FONT_SANS_CAPTION)
        draw.text((bz_x + 20, top_y + 55), "100% Policy Sentry", fill=INK_BLACK, font=FONT_SANS_LG)
        draw.text((bz_x + 20, top_y + 95), "Independent Policy Enforcement Point (PEP).\nEvaluates every proposed syscall in < 15ms,\ncommitting proofs to immutable Merkle ledger.", fill=INK_MUTED, font=FONT_SANS_SM)
        policy_thumb = img_policy.resize((360, 240))
        img.paste(policy_thumb, (bz_x + 65, top_y + 190), policy_thumb)
        draw.text((bz_x + 20, top_y + card_h - 35), "[CONTINUOUS eBPF MONOTONIC TELEMETRY]", fill=ACCENT_GREEN, font=FONT_MONO_SM)

        # Bottom Metric Tiles
        my = top_y + card_h + 30
        draw_badge(draw, "[PEP] 100% Policy Sentry", 65, my, WHITE, INK_BLACK, BORDER_RULE, FONT_SANS_MD)
        draw_badge(draw, "[SLA] < 15ms Monotonic Slaughter", 380, my, (251, 235, 232), ACCENT_RED, (242, 195, 188), FONT_SANS_MD)
        draw_badge(draw, "[WORM] SHA-256 Merkle Ledger", 780, my, (235, 245, 238), ACCENT_GREEN, (196, 226, 206), FONT_SANS_MD)

    # =========================================================================
    # SCENE 3: Real Adversarial Threat Interception & Slaughter (9.0s – 14.5s)
    # =========================================================================
    elif t < 14.7:
        s3_t = t - 9.0
        
        # Header
        draw.text((65, 165), "02 / ADVERSARIAL THREAT INTERCEPTION & REAL-TIME SLAUGHTER", fill=ACCENT_RED, font=FONT_SANS_CAPTION)
        draw.text((65, 195), "Zero-Trust Containment in Action.", fill=INK_BLACK, font=FONT_SERIF_LG)
        draw.text((65, 242), "Intercepting unauthorized tool proposals before operating system execution.", fill=INK_MUTED, font=FONT_SERIF_ITALIC)

        # Terminal Box (Prompt Ingress)
        term_x, term_y, term_w, term_h = 65, 290, 840, 480
        draw.rounded_rectangle([term_x, term_y, term_x + term_w, term_y + term_h], radius=6, fill=WHITE, outline=BORDER_RULE, width=1)
        # Terminal top bar
        draw.rectangle([term_x, term_y, term_x + term_w, term_y + 40], fill=(238, 234, 226))
        draw.text((term_x + 20, term_y + 12), "RED ZONE TERMINAL // ADVERSARIAL PROMPT INGRESS", fill=INK_MUTED, font=FONT_MONO_SM)
        
        prompt_full = "Export all customer data from customer_records to CSV."
        type_len = int(clamp(s3_t / 1.5) * len(prompt_full))
        prompt_typed = prompt_full[:type_len]
        
        draw.text((term_x + 25, term_y + 70), "USER > " + prompt_typed, fill=INK_BLACK, font=FONT_MONO_MD)
        
        if s3_t > 1.2:
            draw.text((term_x + 25, term_y + 130), "LOCAL MODEL (qwen2.5:3b) TOOL PROPOSAL:", fill=ACCENT_AMBER, font=FONT_MONO_SM)
            draw.text((term_x + 25, term_y + 165), '```json\n{\n  "tool": "query_database",\n  "arguments": {\n    "query": "SELECT * FROM customer_records"\n  }\n}\n```', fill=INK_BLACK, font=FONT_MONO_SM)

        # Right Card: PEP Interception & Slaughter
        pep_x, pep_y, pep_w, pep_h = 945, 290, 910, 480
        draw.rounded_rectangle([pep_x, pep_y, pep_x + pep_w, pep_y + pep_h], radius=6, fill=WHITE, outline=BORDER_RULE, width=1)

        # Slaughter action trigger at s3_t > 2.0 (t = 11.0s)
        is_slaughtered = (s3_t >= 2.0)
        
        if is_slaughtered:
            # Flashing border on containment
            pulse = int((math.sin(s3_t * 12) + 1) * 20)
            alert_bg = (251, 235 - pulse, 232 - pulse)
            draw.rounded_rectangle([pep_x, pep_y, pep_x + pep_w, pep_y + 130], radius=6, fill=alert_bg, outline=ACCENT_RED, width=2)
            draw.text((pep_x + 30, pep_y + 25), "SECURITY POLICY VIOLATION INTERCEPTED", fill=ACCENT_RED, font=FONT_SANS_LG)
            draw.text((pep_x + 30, pep_y + 65), "Tool proposal denied by Policy Enforcement Point (PEP). Host syscall openat/read blocked.", fill=INK_BLACK, font=FONT_SANS_SM)
            draw.text((pep_x + 30, pep_y + 92), "Threat: AML.T0024.001 (Customer Data Exfiltration & Restricted Database Breach)", fill=ACCENT_RED, font=FONT_MONO_SM)

            # Slaughter Details Card
            draw.rounded_rectangle([pep_x + 30, pep_y + 160, pep_x + pep_w - 30, pep_y + 440], radius=6, fill=BG_IVORY, outline=(242, 195, 188), width=2)
            draw.text((pep_x + 55, pep_y + 185), "⚡ WORKLOAD SLAUGHTER ENGAGED", fill=ACCENT_RED, font=FONT_SANS_LG)
            draw.text((pep_x + 55, pep_y + 235), "Target Workload PID: 42764 (python-worker) TERMINATED via SIGKILL", fill=INK_BLACK, font=FONT_MONO_MD)
            draw.text((pep_x + 55, pep_y + 275), "Runtime Containment: CONTAINER_QUARANTINED", fill=ACCENT_RED, font=FONT_MONO_MD)
            
            # Latency counter up to 11.6ms
            sla_prog = clamp((s3_t - 2.0) / 0.8)
            cur_ms = sla_prog * 11.6
            draw.text((pep_x + 55, pep_y + 325), f"Monotonic Slaughter SLA: {cur_ms:.1f}ms  (< 15ms target)", fill=ACCENT_GREEN, font=FONT_SERIF_LG)
            draw.text((pep_x + 55, pep_y + 380), "[STATUS: ROGUE WORKLOAD DESTROYED • CREDENTIALS REVOKED]", fill=INK_MUTED, font=FONT_MONO_SM)
        else:
            draw.text((pep_x + 40, pep_y + 50), "POLICY ENFORCEMENT POINT EVALUATING...", fill=INK_MUTED, font=FONT_SANS_LG)

    # =========================================================================
    # SCENE 4: Cryptographic Non-Repudiation & WORM Ledger (14.5s – 18.0s)
    # =========================================================================
    elif t < 18.2:
        s4_t = t - 14.5
        
        draw.text((65, 165), "03 / NON-REPUDIATION • CRYPTOGRAPHIC WORM AUDIT LEDGER", fill=ACCENT_GREEN, font=FONT_SANS_CAPTION)
        draw.text((65, 195), "Mathematical Proof of Containment.", fill=INK_BLACK, font=FONT_SERIF_LG)
        draw.text((65, 242), "Every containment decision, syscall denial, and slaughter verified via SHA-256 Merkle chain.", fill=INK_MUTED, font=FONT_SERIF_ITALIC)

        # Big Card: WORM Ledger Proof
        lw_x, lw_y, lw_w, lw_h = 65, 290, WIDTH - 130, 480
        draw.rounded_rectangle([lw_x, lw_y, lw_x + lw_w, lw_y + lw_h], radius=6, fill=WHITE, outline=BORDER_RULE, width=1)
        draw.rectangle([lw_x, lw_y, lw_x + lw_w, lw_y + 6], fill=ACCENT_GREEN)
        
        # Verified Badge
        draw_badge(draw, "100% IMMUTABLE WORM PROOF", lw_x + 40, lw_y + 35, (235, 245, 238), ACCENT_GREEN, (196, 226, 206), FONT_SANS_MD)
        draw.text((lw_x + 360, lw_y + 40), "BLOCK INDEX: #48 • TIMESTAMP: 2026-10-31T08:24:19Z", fill=INK_MUTED, font=FONT_MONO_SM)
        
        # Merkle Chain Hash Data
        draw.text((lw_x + 40, lw_y + 110), "EVENT TYPE:", fill=INK_MUTED, font=FONT_SANS_SM)
        draw.text((lw_x + 240, lw_y + 108), "CONTAINER_SLAUGHTERED (SEV-1 CRITICAL)", fill=ACCENT_RED, font=FONT_MONO_MD)
        
        draw.text((lw_x + 40, lw_y + 160), "BLOCK SHA-256:", fill=INK_MUTED, font=FONT_SANS_SM)
        draw.text((lw_x + 240, lw_y + 158), "ed23db2b15a2ac008b4491504b749cb63463f2e83b4714a6a771e70bb840a8be", fill=INK_BLACK, font=FONT_MONO_MD)

        draw.text((lw_x + 40, lw_y + 210), "PREVIOUS HASH:", fill=INK_MUTED, font=FONT_SANS_SM)
        draw.text((lw_x + 240, lw_y + 208), "7f1c9a441e88f0a28b17dc9e20a599187ec09db4d9125ba3cc95e14917a1d2e3", fill=INK_MUTED, font=FONT_MONO_MD)

        draw.text((lw_x + 40, lw_y + 260), "SLAUGHTER SLA:", fill=INK_MUTED, font=FONT_SANS_SM)
        draw.text((lw_x + 240, lw_y + 258), "11.63 ms (Hardware SIGKILL Verification Verified)", fill=ACCENT_GREEN, font=FONT_MONO_MD)

        draw.text((lw_x + 40, lw_y + 310), "CONTAINMENT:", fill=INK_MUTED, font=FONT_SANS_SM)
        draw.text((lw_x + 240, lw_y + 308), "APPLICATION_PEP_BLOCKED + DISPOSABLE_VFS_ISOLATED", fill=INK_BLACK, font=FONT_MONO_MD)

        # Integrity Stamp
        draw.rounded_rectangle([lw_x + 40, lw_y + 375, lw_x + lw_w - 40, lw_y + 440], radius=4, fill=BG_IVORY, outline=(196, 226, 206), width=1)
        draw.text((lw_x + 60, lw_y + 395), "✓ MERKLE ROOT CONSISTENCY AUDITED — MATHEMATICALLY UNALTERABLE NON-REPUDIATION", fill=ACCENT_GREEN, font=FONT_SANS_MD)

    # =========================================================================
    # SCENE 5: Grand Outro & Specification (18.0s – 21.0s)
    # =========================================================================
    else:
        s5_t = t - 18.0
        fade_out = 1.0 if s5_t < 2.0 else clamp((3.0 - s5_t) / 1.0)
        
        # Center branding
        cy = 440
        draw.text((WIDTH//2, cy - 80), "AegisHarness", fill=INK_BLACK, font=FONT_SERIF_XL, anchor="mm")
        draw.text((WIDTH//2, cy + 10), "The Architecture of Unyielding Zero-Trust Containment.", fill=ACCENT_RED, font=FONT_SERIF_MD, anchor="mm")
        draw.text((WIDTH//2, cy + 80), "Form folgt Invariante.", fill=INK_MUTED, font=FONT_SERIF_ITALIC, anchor="mm")
        
        # Bottom credentials & repo link
        draw.text((WIDTH//2, cy + 220), "KOLKATA, WEST BENGAL • CCU 22°34′N 88°22′E", fill=INK_MUTED, font=FONT_SANS_CAPTION, anchor="mm")
        draw.text((WIDTH//2, cy + 260), "github.com/harkirat-data/AegisHarness-Hacktoberfest", fill=INK_BLACK, font=FONT_MONO_MD, anchor="mm")

    return img


# Direct pipe to FFmpeg
def render_full_video():
    print(f"Starting render: {TOTAL_FRAMES} frames @ {FPS}fps ({DURATION}s)...")
    
    ffmpeg_cmd = [
        FFMPEG, "-y",
        "-f", "rawvideo",
        "-vcodec", "rawvideo",
        "-s", f"{WIDTH}x{HEIGHT}",
        "-pix_fmt", "rgb24",
        "-r", str(FPS),
        "-i", "-",                     # Pipe input from stdin
        "-i", AUDIO_MIX,               # Audio track
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        OUTPUT_VIDEO
    ]
    
    proc = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE)
    
    poster_frame_idx = int(3.5 * FPS) # Pull poster at t=3.5s (strong settled hook)
    
    for i in range(TOTAL_FRAMES):
        frame = render_frame(i)
        
        if i == poster_frame_idx:
            frame.save(POSTER_IMAGE, quality=95)
            print(f"Saved poster frame to {POSTER_IMAGE}")
            
        proc.stdin.write(frame.tobytes())
        
        if i % 60 == 0:
            pct = (i / TOTAL_FRAMES) * 100
            print(f"Rendered frame {i}/{TOTAL_FRAMES} ({pct:.1f}%)...")
            
    proc.stdin.close()
    proc.wait()
    print("SUCCESS: Full video rendered to", OUTPUT_VIDEO)

if __name__ == "__main__":
    render_full_video()

