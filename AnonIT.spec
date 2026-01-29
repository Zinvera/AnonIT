# -*- mode: python ; coding: utf-8 -*-
"""
AnonIT PyInstaller Spec File
=============================
Build configuration for AnonIT with Messenger support.
"""

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('icon.ico', '.'), 
        ('iconmain.png', '.'),
        ('messenger', 'messenger'),  # Include messenger module
    ],
    hiddenimports=[
        # PyQt6
        'pystray._win32',
        'PyQt6',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'PyQt6.sip',
        # Messenger dependencies
        'websockets',
        'websockets.client',
        'websockets.server',
        'cryptography',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric.x25519',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.primitives.kdf.hkdf',
        'cryptography.hazmat.backends',
        # Messenger module
        'messenger',
        'messenger.client',
        'messenger.protocol',
        'messenger.gui_messenger',
        'messenger.config',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PyQt5',
        'PySide2',
        'PySide6',
        'pygame',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'cv2',
        'tensorflow',
        'torch',
        'IPython',
        'notebook',
        'pytest',
        'sphinx',
        'docutils',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AnonIT',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
)
