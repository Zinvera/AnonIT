#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AnonIT Icon Loader"""

from PIL import Image
import os
import sys

def get_icon_path():
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(__file__)
    return os.path.join(base, 'iconmain.png')

def create_icon(size: int = 64) -> Image.Image:
    try:
        img = Image.open(get_icon_path())
        return img.resize((size, size), Image.Resampling.LANCZOS)
    except:
        # Fallback: create simple icon
        img = Image.new('RGBA', (size, size), (10, 10, 10, 255))
        return img

def create_tray_icon(size: int = 64) -> Image.Image:
    return create_icon(size)

if __name__ == "__main__":
    icon = create_icon(256)
    icon.show()
