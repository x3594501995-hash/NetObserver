from pathlib import Path

from PIL import Image, ImageDraw


def main() -> None:
    size = 1024
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle(
        (72, 72, 952, 952),
        radius=210,
        fill=(24, 42, 75, 255),
        outline=(42, 75, 122, 255),
        width=18,
    )

    center = (512, 512)
    for radius, width, color in (
        (300, 22, (53, 145, 224, 255)),
        (196, 18, (72, 187, 232, 220)),
    ):
        draw.ellipse(
            (
                center[0] - radius,
                center[1] - radius,
                center[0] + radius,
                center[1] + radius,
            ),
            outline=color,
            width=width,
        )

    nodes = [(512, 250), (285, 660), (739, 660)]
    for start, end in ((nodes[0], nodes[1]), (nodes[1], nodes[2]), (nodes[2], nodes[0])):
        draw.line((start, end), fill=(90, 185, 235, 230), width=24)

    for x, y in nodes:
        draw.ellipse(
            (x - 54, y - 54, x + 54, y + 54),
            fill=(92, 218, 181, 255),
            outline=(202, 255, 239, 255),
            width=12,
        )

    draw.ellipse(
        (center[0] - 34, center[1] - 34, center[0] + 34, center[1] + 34),
        fill=(255, 255, 255, 255),
    )

    output = Path(__file__).with_name("netobserver.ico")
    image.resize((256, 256), Image.Resampling.LANCZOS).save(
        output,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


if __name__ == "__main__":
    main()
