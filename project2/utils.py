import numpy as np
import cv2
from scipy.fftpack import dct, idct
import os

DESKTOP_PATH = os.path.join(os.path.expanduser("~"), "Desktop")

def dct2(block):
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

def idct2(block):
    return idct(idct(block.T, norm='ortho').T, norm='ortho')

def read_image_gray(path):
    img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise FileNotFoundError(f"图像 {path} 不存在或无法读取")
    return img

def read_watermark(path):
    wm = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if wm is None:
        raise FileNotFoundError(f"水印 {path} 不存在或无法读取")
    return (wm > 128).astype(np.uint8)

def block_process(image, block_size=8):
    # 确保图像尺寸是block_size的倍数
    h, w = image.shape
    h = h // block_size * block_size
    w = w // block_size * block_size
    cropped = image[:h, :w]
    return (cropped.reshape(h//block_size, block_size, -1, block_size)
            .swapaxes(1, 2)
            .reshape(-1, block_size, block_size))

def merge_blocks(blocks, image_shape):
    block_size = blocks.shape[1]
    h, w = image_shape
    h = h // block_size * block_size
    w = w // block_size * block_size
    return (blocks.reshape(h//block_size, w//block_size, block_size, block_size)
            .swapaxes(1, 2)
            .reshape(h, w))

def embed_single_block(dct_block, watermark_bit, alpha=25.0):
    if watermark_bit == 1:
        dct_block[4, 3] += alpha
        dct_block[3, 4] += alpha
    else:
        dct_block[4, 3] -= alpha
        dct_block[3, 4] -= alpha
    return dct_block

def extract_single_block(dct_block, alpha=25.0):
    diff = dct_block[4, 3] + dct_block[3, 4]
    return 1 if diff > 0 else 0