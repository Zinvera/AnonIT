#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT - Icon Generation
=========================

Generates the application icon programmatically using PIL.

Author: AnonIT Project
License: MIT
"""

from PIL import Image, ImageDraw


def create_icon(size: int = 64) -> Image.Image:
    """
    Create the AnonIT icon.
    
    Args:
        size: Icon size in pixels.
        
    Returns:
        PIL Image object.
    """
    # Create image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Colors
    bg_color = (10, 10, 10, 255)
    accent_color = (0, 212, 170, 255)  # #00d4aa
    
    # Draw rounded rectangle background
    padding = size // 8
    draw.rounded_rectangle(
        [padding, padding, size - padding, size - padding],
        radius=size // 6,
        fill=bg_color
    )
    
    # Draw lock symbol
    center_x = size // 2
    center_y = size // 2
    
    # Lock body
    body_width = size // 3
    body_height = size // 4
    body_left = center_x - body_width // 2
    body_top = center_y - body_height // 4
    
    draw.rounded_rectangle(
        [body_left, body_top, body_left + body_width, body_top + body_height],
        radius=size // 16,
        fill=accent_color
    )
    
    # Lock shackle (arc)
    shackle_width = body_width * 0.6
    shackle_height = body_height * 0.8
    shackle_left = center_x - shackle_width // 2
    shackle_top = body_top - shackle_height
    
    draw.arc(
        [shackle_left, shackle_top, shackle_left + shackle_width, body_top + size // 16],
        start=180,
        end=0,
        fill=accent_color,
        width=max(2, size // 16)
    )
    
    return img


def create_tray_icon(size: int = 64) -> Image.Image:
    """
    Create the system tray icon.
    
    Args:
        size: Icon size in pixels.
        
    Returns:
        PIL Image object suitable for system tray.
    """
    return create_icon(size)


if __name__ == "__main__":
    # Test icon generation
    icon = create_icon(256)
    icon.save("test_icon.png")
    print("Icon saved to test_icon.png")
