import cv2
import numpy as np
import matplotlib.pyplot as plt
from skimage.metrics import structural_similarity as ssim
from PIL import Image, ImageEnhance
import os

class DigitalWatermark:
    def __init__(self, watermark_strength=0.05):
        self.watermark_strength = watermark_strength

    def _dct_block_process(self, block):
        """对8x8块进行DCT变换"""
        return cv2.dct(np.float32(block))

    def _idct_block_process(self, block):
        """对8x8块进行逆DCT变换"""
        return cv2.idct(np.float32(block))

    def _get_embed_positions(self, block_size=8):
        """获取水印嵌入位置(中频系数)"""
        positions = []
        for i in range(1, 5):
            for j in range(1, 5):
                if i + j > 2:  # 避开低频区域
                    positions.append((i, j))
        return positions

    def embed_watermark(self, host_img, watermark_img):
        """
        在宿主图像中嵌入水印
        :param host_img: 宿主图像 (numpy数组)
        :param watermark_img: 水印图像 (numpy数组)
        :return: 含水印的图像 (numpy数组)
        """
        # 将水印图像调整为二值图像
        watermark = cv2.resize(watermark_img, (host_img.shape[1] // 8, host_img.shape[0] // 8))
        watermark = cv2.threshold(watermark, 128, 255, cv2.THRESH_BINARY)[1]
        watermark = watermark / 255.0  # 归一化到[0,1]

        # 转换为YUV颜色空间
        yuv_host = cv2.cvtColor(host_img, cv2.COLOR_BGR2YUV)
        y_channel = np.float32(yuv_host[:, :, 0])

        # 获取水印嵌入位置
        positions = self._get_embed_positions()

        # 分块处理
        watermarked_y = np.zeros_like(y_channel)
        watermark_idx = 0

        for i in range(0, y_channel.shape[0], 8):
            for j in range(0, y_channel.shape[1], 8):
                block = y_channel[i:i + 8, j:j + 8]
                if block.shape[0] == 8 and block.shape[1] == 8:
                    # DCT变换
                    dct_block = self._dct_block_process(block)

                    # 嵌入水印
                    for pos in positions:
                        if watermark_idx < watermark.size:
                            row, col = pos
                            # 根据水印值调整系数
                            if watermark.flat[watermark_idx] > 0.5:
                                dct_block[row, col] += self.watermark_strength * dct_block[row, col]
                            else:
                                dct_block[row, col] -= self.watermark_strength * dct_block[row, col]
                            watermark_idx += 1

                    # 逆DCT变换
                    watermarked_block = self._idct_block_process(dct_block)
                    watermarked_y[i:i + 8, j:j + 8] = watermarked_block

        # 合并通道
        yuv_host[:, :, 0] = np.clip(watermarked_y, 0, 255)
        watermarked_img = cv2.cvtColor(yuv_host, cv2.COLOR_YUV2BGR)

        return np.uint8(watermarked_img)

    def extract_watermark(self, watermarked_img, original_img=None, watermark_shape=(64, 64)):
        """
        从含水印图像中提取水印
        :param watermarked_img: 含水印的图像
        :param original_img: 原始宿主图像(可选)
        :param watermark_shape: 水印图像形状
        :return: 提取的水印图像
        """
        # 转换为YUV颜色空间
        yuv_watermarked = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2YUV)
        y_watermarked = np.float32(yuv_watermarked[:, :, 0])

        if original_img is not None:
            yuv_original = cv2.cvtColor(original_img, cv2.COLOR_BGR2YUV)
            y_original = np.float32(yuv_original[:, :, 0])
        else:
            y_original = None

        # 获取水印嵌入位置
        positions = self._get_embed_positions()

        # 初始化水印数组
        watermark = np.zeros(watermark_shape)
        watermark_idx = 0

        # 分块处理
        for i in range(0, y_watermarked.shape[0], 8):
            for j in range(0, y_watermarked.shape[1], 8):
                block_w = y_watermarked[i:i + 8, j:j + 8]
                if block_w.shape[0] == 8 and block_w.shape[1] == 8:
                    # DCT变换
                    dct_w = self._dct_block_process(block_w)

                    if y_original is not None:
                        block_o = y_original[i:i + 8, j:j + 8]
                        dct_o = self._dct_block_process(block_o)

                    # 提取水印
                    for pos in positions:
                        if watermark_idx < watermark.size:
                            row, col = pos
                            # 比较系数变化
                            if y_original is not None:
                                # 如果有原始图像，计算系数变化
                                change = dct_w[row, col] - dct_o[row, col]
                                watermark.flat[watermark_idx] = 1 if change > 0 else 0
                            else:
                                # 没有原始图像，使用统计方法
                                # 这里简化处理，实际应用中需要更复杂的算法
                                watermark.flat[watermark_idx] = 1 if dct_w[row, col] > 0 else 0
                            watermark_idx += 1

        # 二值化水印
        watermark = np.uint8(watermark * 255)
        return watermark

    def robustness_test(self, watermarked_img, original_watermark, attacks):
        """
        鲁棒性测试
        :param watermarked_img: 含水印的图像
        :param original_watermark: 原始水印图像
        :param attacks: 攻击操作列表
        :return: 测试结果字典
        """
        results = {}

        for attack_name, attack_func in attacks.items():
            # 应用攻击
            attacked_img = attack_func(watermarked_img.copy())

            # 提取水印
            extracted_watermark = self.extract_watermark(attacked_img, watermark_shape=original_watermark.shape[:2])

            # 计算相似度
            original_binary = cv2.threshold(original_watermark, 128, 255, cv2.THRESH_BINARY)[1]
            extracted_binary = cv2.threshold(extracted_watermark, 128, 255, cv2.THRESH_BINARY)[1]

            # 调整大小一致
            extracted_binary = cv2.resize(extracted_binary, (original_binary.shape[1], original_binary.shape[0]))

            # 计算SSIM
            ssim_value = ssim(original_binary, extracted_binary)

            # 计算误码率
            total_pixels = original_binary.size
            error_pixels = np.sum(original_binary != extracted_binary)
            ber = error_pixels / total_pixels

            results[attack_name] = {
                'image': attacked_img,
                'watermark': extracted_watermark,
                'ssim': ssim_value,
                'ber': ber
            }

        return results


# 攻击操作定义
def rotate_attack(img, angle=5):
    """旋转攻击"""
    rows, cols = img.shape[:2]
    M = cv2.getRotationMatrix2D((cols / 2, rows / 2), angle, 1)
    return cv2.warpAffine(img, M, (cols, rows))


def crop_attack(img, ratio=0.1):
    """裁剪攻击"""
    h, w = img.shape[:2]
    crop_h = int(h * ratio)
    crop_w = int(w * ratio)
    cropped = img[crop_h:h - crop_h, crop_w:w - crop_w]
    return cv2.resize(cropped, (w, h))


def contrast_attack(img, factor=1.5):
    """对比度调整攻击"""
    pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    enhancer = ImageEnhance.Contrast(pil_img)
    enhanced = enhancer.enhance(factor)
    return cv2.cvtColor(np.array(enhanced), cv2.COLOR_RGB2BGR)


def brightness_attack(img, factor=1.5):
    """亮度调整攻击"""
    pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    enhancer = ImageEnhance.Brightness(pil_img)
    enhanced = enhancer.enhance(factor)
    return cv2.cvtColor(np.array(enhanced), cv2.COLOR_RGB2BGR)


def gaussian_noise_attack(img, mean=0, sigma=25):
    """高斯噪声攻击"""
    noise = np.random.normal(mean, sigma, img.shape).astype(np.uint8)
    noisy_img = cv2.add(img, noise)
    return np.clip(noisy_img, 0, 255)


def jpeg_compression_attack(img, quality=50):
    """JPEG压缩攻击"""
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
    _, encimg = cv2.imencode('.jpg', img, encode_param)
    return cv2.imdecode(encimg, 1)


def blur_attack(img, kernel_size=5):
    """模糊攻击"""
    return cv2.GaussianBlur(img, (kernel_size, kernel_size), 0)


def scaling_attack(img, scale=0.5):
    """缩放攻击"""
    h, w = img.shape[:2]
    scaled = cv2.resize(img, (int(w * scale), int(h * scale)))
    return cv2.resize(scaled, (w, h))


# 测试函数
def test_watermark_system():
    # 创建示例图像
    host_img = np.ones((512, 512, 3), dtype=np.uint8) * 255
    cv2.putText(host_img, 'Host Image', (150, 256), cv2.FONT_HERSHEY_SIMPLEX, 2, (0, 0, 0), 4)

    watermark_img = np.zeros((64, 64), dtype=np.uint8)
    cv2.putText(watermark_img, 'W', (20, 45), cv2.FONT_HERSHEY_SIMPLEX, 1.5, 255, 3)

    # 创建水印系统
    watermark_system = DigitalWatermark(watermark_strength=0.08)

    # 嵌入水印
    watermarked_img = watermark_system.embed_watermark(host_img, watermark_img)

    # 定义攻击操作
    attacks = {
        'Original': lambda x: x,
        'Rotation (5°)': lambda x: rotate_attack(x, 5),
        'Cropping (10%)': lambda x: crop_attack(x, 0.1),
        'Contrast Increase': lambda x: contrast_attack(x, 1.8),
        'Contrast Decrease': lambda x: contrast_attack(x, 0.5),
        'Brightness Increase': lambda x: brightness_attack(x, 1.5),
        'Brightness Decrease': lambda x: brightness_attack(x, 0.7),
        'Gaussian Noise': lambda x: gaussian_noise_attack(x, sigma=30),
        'JPEG Compression': lambda x: jpeg_compression_attack(x, quality=30),
        'Blurring': lambda x: blur_attack(x, kernel_size=7),
        'Scaling': lambda x: scaling_attack(x, scale=0.6)
    }

    # 进行鲁棒性测试
    results = watermark_system.robustness_test(watermarked_img, watermark_img, attacks)

    # 计算需要的行数
    num_attacks = len(attacks)
    rows_per_attack = 2  # 每个攻击占2行（图像+水印）
    total_rows = 1 + (num_attacks + 2) // 3 * rows_per_attack  # 1行用于原始图像，其余用于攻击

    # 显示结果
    plt.figure(figsize=(15, total_rows * 4))

    # 显示原始图像和水印
    plt.subplot(total_rows, 3, 1)
    plt.imshow(cv2.cvtColor(host_img, cv2.COLOR_BGR2RGB))
    plt.title('Original Host Image')
    plt.axis('off')

    plt.subplot(total_rows, 3, 2)
    plt.imshow(watermark_img, cmap='gray')
    plt.title('Original Watermark')
    plt.axis('off')

    plt.subplot(total_rows, 3, 3)
    plt.imshow(cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2RGB))
    plt.title('Watermarked Image')
    plt.axis('off')

    # 显示攻击后的图像和提取的水印
    for i, (attack_name, result) in enumerate(results.items()):
        # 计算位置
        row_start = 1 + (i // 3) * 2
        col = i % 3

        # 攻击后的图像位置
        img_pos = row_start * 3 + col + 1
        plt.subplot(total_rows, 3, img_pos)
        plt.imshow(cv2.cvtColor(result['image'], cv2.COLOR_BGR2RGB))
        plt.title(f'{attack_name}\nSSIM: {result["ssim"]:.3f}, BER: {result["ber"]:.3f}')
        plt.axis('off')

        # 提取的水印位置
        wm_pos = (row_start + 1) * 3 + col + 1
        plt.subplot(total_rows, 3, wm_pos)
        plt.imshow(result['watermark'], cmap='gray')
        plt.title(f'Extracted Watermark')
        plt.axis('off')

    plt.tight_layout()
    plt.savefig('watermark_robustness_test.png', dpi=200)
    plt.show()


if __name__ == "__main__":
    test_watermark_system()