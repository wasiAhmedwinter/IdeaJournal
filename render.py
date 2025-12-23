from moviepy.video.VideoClip import VideoClip
import numpy as np
from PIL import Image
import math
import random

# Load snowflake PNG
flake = Image.open("static/snow.png").convert("RGBA")

W, H = 1920, 1080  # video size
DURATION = 8       # seconds
FPS = 30

flakes = []
for i in range(220):
    x = random.random()*W
    y = random.random()*H
    speed = random.random()*100+50
    size = random.uniform(0.2, 1.2)
    rot_speed = random.uniform(-0.5, 0.5)
    flakes.append((x, y, speed, size, rot_speed))

def make_frame(t):
    frame = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    for idx, (x0, y0, speed, size, rot_speed) in enumerate(flakes):
        y = (y0 + speed*t) % (H + 50) - 50
        x = x0 + math.sin(y/50)*20
        fl = flake.resize((int(flake.width*size), int(flake.height*size)))
        fl = fl.rotate(rot_speed*t*30, expand=True)
        frame.paste(fl, (int(x), int(y)), fl)

    return np.array(frame)

clip = VideoClip(make_frame, duration=DURATION)
clip.write_videofile("snow_loop.mp4", fps=FPS, codec="libx264", audio=False)
