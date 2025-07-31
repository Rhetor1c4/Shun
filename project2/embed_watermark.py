import cv2
import numpy as np
from utils import *
import os


def embed_watermark(host_img_path, watermark_img_path, output_path, alpha=25.0):
    host_img = read_image_gray(host_img_path)
    watermark = read_watermark(watermark_img_path)

    # 计算实际可嵌入的块数量
    block_count = (host_img.shape[0] // 8) * (host_img.shape[1] // 8)

    # 调整水印尺寸以匹配块数量
    wm_size = int(np.sqrt(block_count))
    watermark = cv2.resize(watermark, (wm_size, wm_size))
    watermark_flat = watermark.flatten()

    # 分块处理
    blocks = block_process(host_img)
    watermarked_blocks = []

    for i, block in enumerate(blocks):
        dct_block = dct2(block.astype(np.float32))
        if i < len(watermark_flat):
            modified_block = embed_single_block(dct_block, watermark_flat[i], alpha)
        else:
            modified_block = dct_block
        watermarked_blocks.append(idct2(modified_block))

    # 合并并保存
    watermarked_img = merge_blocks(np.array(watermarked_blocks), host_img.shape)
    watermarked_img = np.clip(watermarked_img, 0, 255).astype(np.uint8)
    cv2.imwrite(output_path, watermarked_img)
    print(f"水印嵌入完成，保存到 {output_path}")
    return watermarked_img


if __name__ == "__main__":
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    embed_watermark(
        os.path.join(desktop, "lena.png"),
        os.path.join(desktop, "watermark.png"),
        os.path.join(desktop, "watermarked.png")
    )