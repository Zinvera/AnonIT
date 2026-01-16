#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonIT - Lucide Icons for PyQt6
================================

SVG icons from Lucide (https://lucide.dev) rendered as QIcon.

Author: AnonIT Project
License: MIT
"""

from PyQt6.QtCore import Qt, QSize, QRectF
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QPen, QPainterPath
from PyQt6.QtWidgets import QPushButton


def create_icon(draw_func, size=24, color="#ffffff", stroke_width=2):
    """Create a QIcon from a draw function."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    
    pen = QPen(QColor(color))
    pen.setWidthF(stroke_width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    
    # Scale factor (Lucide uses 24x24 viewbox)
    scale = size / 24.0
    painter.scale(scale, scale)
    
    draw_func(painter)
    painter.end()
    
    return QIcon(pixmap)


def draw_eye(painter):
    """Lucide 'eye' icon."""
    path = QPainterPath()
    # Eye outline
    path.moveTo(1, 12)
    path.cubicTo(1, 12, 5, 4, 12, 4)
    path.cubicTo(19, 4, 23, 12, 23, 12)
    path.cubicTo(23, 12, 19, 20, 12, 20)
    path.cubicTo(5, 20, 1, 12, 1, 12)
    painter.drawPath(path)
    # Pupil
    painter.drawEllipse(QRectF(9, 9, 6, 6))


def draw_eye_off(painter):
    """Lucide 'eye-off' icon."""
    path = QPainterPath()
    path.moveTo(17.94, 17.94)
    path.cubicTo(16.23, 19.24, 14.18, 20, 12, 20)
    path.cubicTo(5, 20, 1, 12, 1, 12)
    path.cubicTo(1, 12, 2.74, 8.87, 5.64, 6.64)
    painter.drawPath(path)
    
    path2 = QPainterPath()
    path2.moveTo(6.06, 6.06)
    path2.cubicTo(7.77, 4.76, 9.82, 4, 12, 4)
    path2.cubicTo(19, 4, 23, 12, 23, 12)
    path2.cubicTo(23, 12, 21.26, 15.13, 18.36, 17.36)
    painter.drawPath(path2)
    
    # Diagonal line
    painter.drawLine(1, 1, 23, 23)


def draw_lock(painter):
    """Lucide 'lock' icon."""
    # Lock body
    painter.drawRoundedRect(QRectF(3, 11, 18, 11), 2, 2)
    # Shackle
    path = QPainterPath()
    path.moveTo(7, 11)
    path.lineTo(7, 7)
    path.cubicTo(7, 4.24, 9.24, 2, 12, 2)
    path.cubicTo(14.76, 2, 17, 4.24, 17, 7)
    path.lineTo(17, 11)
    painter.drawPath(path)


def draw_unlock(painter):
    """Lucide 'unlock' icon."""
    # Lock body
    painter.drawRoundedRect(QRectF(3, 11, 18, 11), 2, 2)
    # Open shackle
    path = QPainterPath()
    path.moveTo(7, 11)
    path.lineTo(7, 7)
    path.cubicTo(7, 4.24, 9.24, 2, 12, 2)
    path.cubicTo(14.76, 2, 17, 4.24, 17, 7)
    painter.drawPath(path)


def draw_copy(painter):
    """Lucide 'copy' icon."""
    # Back rectangle
    painter.drawRoundedRect(QRectF(9, 9, 13, 13), 2, 2)
    # Front rectangle
    path = QPainterPath()
    path.moveTo(5, 15)
    path.lineTo(4, 15)
    path.cubicTo(2.9, 15, 2, 14.1, 2, 13)
    path.lineTo(2, 4)
    path.cubicTo(2, 2.9, 2.9, 2, 4, 2)
    path.lineTo(13, 2)
    path.cubicTo(14.1, 2, 15, 2.9, 15, 4)
    path.lineTo(15, 5)
    painter.drawPath(path)


def draw_check(painter):
    """Lucide 'check' icon."""
    path = QPainterPath()
    path.moveTo(20, 6)
    path.lineTo(9, 17)
    path.lineTo(4, 12)
    painter.drawPath(path)


def draw_x(painter):
    """Lucide 'x' icon."""
    painter.drawLine(18, 6, 6, 18)
    painter.drawLine(6, 6, 18, 18)


def draw_trash(painter):
    """Lucide 'trash-2' icon."""
    path = QPainterPath()
    path.moveTo(3, 6)
    path.lineTo(21, 6)
    painter.drawPath(path)
    
    path2 = QPainterPath()
    path2.moveTo(19, 6)
    path2.lineTo(19, 20)
    path2.cubicTo(19, 21.1, 18.1, 22, 17, 22)
    path2.lineTo(7, 22)
    path2.cubicTo(5.9, 22, 5, 21.1, 5, 20)
    path2.lineTo(5, 6)
    painter.drawPath(path2)
    
    painter.drawLine(8, 2, 16, 2)
    painter.drawLine(10, 11, 10, 17)
    painter.drawLine(14, 11, 14, 17)


# Pre-built icons
class Icons:
    """Pre-built Lucide icons."""
    
    @staticmethod
    def eye(size=20, color="#ffffff"):
        return create_icon(draw_eye, size, color)
    
    @staticmethod
    def eye_off(size=20, color="#ffffff"):
        return create_icon(draw_eye_off, size, color)
    
    @staticmethod
    def lock(size=20, color="#ffffff"):
        return create_icon(draw_lock, size, color)
    
    @staticmethod
    def unlock(size=20, color="#ffffff"):
        return create_icon(draw_unlock, size, color)
    
    @staticmethod
    def copy(size=20, color="#ffffff"):
        return create_icon(draw_copy, size, color)
    
    @staticmethod
    def check(size=20, color="#ffffff"):
        return create_icon(draw_check, size, color)
    
    @staticmethod
    def x(size=20, color="#ffffff"):
        return create_icon(draw_x, size, color)
    
    @staticmethod
    def trash(size=20, color="#ffffff"):
        return create_icon(draw_trash, size, color)
