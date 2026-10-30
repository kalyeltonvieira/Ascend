def ror13(name):
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

funcs = [
    "LdrLoadDll",
    "RegisterClassA",
    "CreateWindowExA",
    "DefWindowProcA",
    "PeekMessageA",
    "TranslateMessage",
    "DispatchMessageA",
    "GetDC",
    "ReleaseDC",
    "GetAsyncKeyState",
    "PostQuitMessage",
    "ShowCursor",
    "CreateCompatibleDC",
    "CreateCompatibleBitmap",
    "SelectObject",
    "DeleteObject",
    "DeleteDC",
    "PatBlt",
    "CreateSolidBrush",
    "CreatePen",
    "Rectangle",
    "Ellipse",
    "MoveToEx",
    "LineTo",
    "SetTextColor",
    "SetBkMode",
    "TextOutA",
    "BitBlt"
]

print("; ROR13 API Hashes")
for f in funcs:
    print(f"hash_{f} equ 0x{ror13(f):08X} ; {f}")
