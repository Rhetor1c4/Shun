import cv2
import numpy as np
from utils import *
import os

def extract_watermark(watermarked_img_path, original_img_path, output_path, alpha=25.0):
    watermarked_img = read_image_gray(watermarked_img_path)
    original_img = read_image_gray(original_img_path)

    # 统一尺寸
    h, w = original_img.shape
    watermarked_img = watermarked_img[:h, :w]

    # 分块处理
    blocks_orig = block_process(original_img)
    blocks_wm = block_process(watermarked_img)

    # 提取水印位
    watermark_bits = []
    for orig_block, wm_block in zip(blocks_orig, blocks_wm):
        orig_dct = dct2(orig_block.astype(np.float32))
        wm_dct = dct2(wm_block.astype(np.float32))
        diff_dct = wm_dct - orig_dct
        watermark_bits.append(extract_single_block(diff_dct, alpha))

    # 动态计算水印尺寸
    total_bits = len(watermark_bits)
    wm_size = int(np.sqrt(total_bits))
    watermark = np.array(watermark_bits[:wm_size * wm_size]).reshape(wm_size, wm_size)

    # 保存结果
    watermark_img = (watermark * 255).astype(np.uint8)
    cv2.imwrite(output_path, watermark_img)
    print(f"水印提取完成，保存到 {output_path}")
    return watermark_img


if __name__ == "__main__":
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    extract_watermark(
        os.path.join(desktop, "watermarked.png"),
        os.path.join(desktop, "lena.png"),
        os.path.join(desktop, "extracted_watermark.png")
    )