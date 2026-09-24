"""生成 NetFlow 应用图标（多尺寸 .ico + 1024 PNG 母版）。

图形：蓝色渐变圆角方块 + 白色「N」形流向线（起点白色节点 → 终点绿色节点），
寓意「从源端出发、沿路径抵达目标」的网络诊断链路；绿色终点与产品状态色（通过）一致。

用法：python scripts/generate_icon.py
依赖：Pillow
输出：src/NetFlow.Desktop/Assets/NetFlow.ico、NetFlow-icon-1024.png
"""
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "src" / "NetFlow.Desktop" / "Assets"

MASTER = 2048  # 超采样母版，缩小后边缘更平滑
S = MASTER / 1024  # 以 1024 坐标系设计，按比例放大

BLUE_TOP = (59, 130, 246)  # #3B82F6
BLUE_BOTTOM = (29, 78, 216)  # #1D4ED8
WHITE = (255, 255, 255, 255)
GREEN = (74, 222, 128, 255)  # #4ADE80


def p(x: float, y: float) -> tuple[float, float]:
    return x * S, y * S


def circle(draw: ImageDraw.ImageDraw, cx: float, cy: float, r: float, fill) -> None:
    draw.ellipse([(cx - r) * S, (cy - r) * S, (cx + r) * S, (cy + r) * S], fill=fill)


def build_master() -> Image.Image:
    size = MASTER
    # 垂直渐变背景
    bg = Image.new("RGBA", (size, size))
    px = ImageDraw.Draw(bg)
    for y in range(size):
        t = y / (size - 1)
        color = tuple(round(BLUE_TOP[i] + (BLUE_BOTTOM[i] - BLUE_TOP[i]) * t) for i in range(3))
        px.line([(0, y), (size, y)], fill=color + (255,))

    # 圆角方块遮罩
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=int(230 * S), fill=255)
    bg.putalpha(mask)

    draw = ImageDraw.Draw(bg)

    # 「N」形流向线：A(左下) → B(左上) → C(右下) → D(右上)
    a, b, c, d = (292, 730), (292, 294), (732, 730), (732, 294)
    width = int(92 * S)
    path = [p(*a), p(*b), p(*c), p(*d)]
    draw.line(path, fill=WHITE, width=width, joint="curve")
    for x, y in (a, b, c):  # 圆头端点/转角
        circle(draw, x, y, 46, WHITE)

    # 起点：白色节点（内置蓝点，呈「网络节点」感）
    circle(draw, a[0], a[1], 100, WHITE)
    circle(draw, a[0], a[1], 44, BLUE_BOTTOM + (255,))
    # 终点：绿色节点（通过/到达）
    circle(draw, d[0], d[1], 100, WHITE)
    circle(draw, d[0], d[1], 70, GREEN)
    return bg


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    master = build_master()

    master.resize((1024, 1024), Image.LANCZOS).save(OUT_DIR / "NetFlow-icon-1024.png")

    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    frames = [master.resize((s, s), Image.LANCZOS) for s in sizes]
    frames[-1].save(
        OUT_DIR / "NetFlow.ico",
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=frames[:-1],
    )
    print(f"已生成：{OUT_DIR / 'NetFlow.ico'}")


if __name__ == "__main__":
    main()
