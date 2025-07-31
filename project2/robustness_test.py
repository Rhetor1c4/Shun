import cv2
import numpy as np
from embed_watermark import embed_watermark
from extract_watermark import extract_watermark
from utils import read_watermark, DESKTOP_PATH
import os


def apply_attacks(image_path, output_dir):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    attacked_images = {}

    # 1. 水平翻转
    flipped = cv2.flip(img, 1)
    cv2.imwrite(os.path.join(output_dir, "flipped.png"), flipped)
    attacked_images['flipped'] = flipped

    # 2. 裁剪 (20%)
    h, w = img.shape
    cropped = img[int(h * 0.1):int(h * 0.9), int(w * 0.1):int(w * 0.9)]
    cv2.imwrite(os.path.join(output_dir, "cropped.png"), cropped)
    attacked_images['cropped'] = cropped

    # 3. 对比度调整 (+50%)
    contrast = np.clip(img * 1.5, 0, 255).astype(np.uint8)
    cv2.imwrite(os.path.join(output_dir, "contrast.png"), contrast)
    attacked_images['contrast'] = contrast

    # 4. 旋转 (15度)
    M = cv2.getRotationMatrix2D((w / 2, h / 2), 15, 1)
    rotated = cv2.warpAffine(img, M, (w, h))
    cv2.imwrite(os.path.join(output_dir, "rotated.png"), rotated)
    attacked_images['rotated'] = rotated

    return attacked_images


def test_robustness():
    # 路径设置
    watermarked_path = os.path.join(DESKTOP_PATH, "watermarked.png")
    output_dir = DESKTOP_PATH

    # 嵌入水印
    embed_watermark(
        os.path.join(DESKTOP_PATH, "lena.png"),
        os.path.join(DESKTOP_PATH, "watermark.png"),
        watermarked_path
    )

    # 应用攻击
    attacked_images = apply_attacks(watermarked_path, output_dir)

    # 测试每种攻击
    for attack_name, attacked_img in attacked_images.items():
        temp_path = os.path.join(output_dir, f"{attack_name}_temp.png")
        extracted_path = os.path.join(output_dir, f"{attack_name}_extracted.png")

        cv2.imwrite(temp_path, attacked_img)
        extracted = extract_watermark(temp_path, watermarked_path, extracted_path)

        # 计算NC值（需手动对比原始水印）
        print(f"{attack_name} 攻击测试完成，提取结果保存到 {extracted_path}")


if __name__ == "__main__":
    test_robustness()