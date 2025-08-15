#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>
#include <wmmintrin.h>

// SM4常量定义
#define SM4_BLOCK_SIZE 16
#define SM4_NUM_ROUNDS 32

// SM4 S盒
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// SM4固定参数
static const uint32_t FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 辅助宏
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define LOAD32U(p) (*(const uint32_t *)(p))
#define STORE32U(p, v) (*(uint32_t *)(p) = (v))

// 基本实现
void sm4_key_schedule(const uint8_t* key, uint32_t* rk) {
    uint32_t k[4];
    for (int i = 0; i < 4; i++) {
        k[i] = LOAD32U(key + i * 4) ^ FK[i];
    }

    for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
        uint32_t tmp = k[1] ^ k[2] ^ k[3] ^ CK[i];
        uint32_t sbox_out = SM4_SBOX[tmp & 0xFF] |
            (SM4_SBOX[(tmp >> 8) & 0xFF] << 8) |
            (SM4_SBOX[(tmp >> 16) & 0xFF] << 16) |
            (SM4_SBOX[(tmp >> 24) & 0xFF] << 24);

        rk[i] = k[0] ^ sbox_out ^ ROTL32(sbox_out, 13) ^ ROTL32(sbox_out, 23);
        k[0] = k[1]; k[1] = k[2]; k[2] = k[3]; k[3] = rk[i];
    }
}

static uint32_t sm4_t(uint32_t x) {
    uint32_t t = SM4_SBOX[x & 0xFF] |
        (SM4_SBOX[(x >> 8) & 0xFF] << 8) |
        (SM4_SBOX[(x >> 16) & 0xFF] << 16) |
        (SM4_SBOX[(x >> 24) & 0xFF] << 24);
    return t ^ ROTL32(t, 2) ^ ROTL32(t, 10) ^ ROTL32(t, 18) ^ ROTL32(t, 24);
}

void sm4_encrypt(const uint32_t* rk, const uint8_t* in, uint8_t* out) {
    uint32_t x[4];
    for (int i = 0; i < 4; i++) {
        x[i] = LOAD32U(in + i * 4);
    }

    for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
        uint32_t tmp = x[0] ^ sm4_t(x[1] ^ x[2] ^ x[3] ^ rk[i]);
        x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = tmp;
    }

    STORE32U(out, x[3]); STORE32U(out + 4, x[2]);
    STORE32U(out + 8, x[1]); STORE32U(out + 12, x[0]);
}

// T-table优化
static uint32_t T0[256], T1[256], T2[256], T3[256];

void sm4_init_ttable() {
    for (int i = 0; i < 256; i++) {
        uint32_t s = SM4_SBOX[i];
        uint32_t t = s ^ ROTL32(s, 2) ^ ROTL32(s, 10) ^ ROTL32(s, 18) ^ ROTL32(s, 24);
        T0[i] = t;
        T1[i] = ROTL32(t, 24);
        T2[i] = ROTL32(t, 16);
        T3[i] = ROTL32(t, 8);
    }
}

void sm4_encrypt_ttable(const uint32_t* rk, const uint8_t* in, uint8_t* out) {
    uint32_t x[4];
    for (int i = 0; i < 4; i++) {
        x[i] = LOAD32U(in + i * 4);
    }

    for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
        uint32_t tmp = x[0] ^
            T0[(x[1] >> 24) & 0xFF] ^
            T1[(x[1] >> 16) & 0xFF] ^
            T2[(x[1] >> 8) & 0xFF] ^
            T3[x[1] & 0xFF] ^
            rk[i];

        x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = tmp;
    }

    STORE32U(out, x[3]); STORE32U(out + 4, x[2]);
    STORE32U(out + 8, x[1]); STORE32U(out + 12, x[0]);
}

// AESNI优化
#ifdef __AES__
__m128i sm4_sbox_aesni(__m128i x) {
    // 使用AESNI指令实现S盒近似
    x = _mm_aesenc_si128(x, _mm_setzero_si128());
    return x;
}

__m128i sm4_linear(__m128i x) {
    __m128i t2 = _mm_xor_si128(_mm_slli_epi32(x, 2), _mm_srli_epi32(x, 30));
    __m128i t10 = _mm_xor_si128(_mm_slli_epi32(x, 10), _mm_srli_epi32(x, 22));
    __m128i t18 = _mm_xor_si128(_mm_slli_epi32(x, 18), _mm_srli_epi32(x, 14));
    __m128i t24 = _mm_xor_si128(_mm_slli_epi32(x, 24), _mm_srli_epi32(x, 8));
    return _mm_xor_si128(x, _mm_xor_si128(t2, _mm_xor_si128(t10, _mm_xor_si128(t18, t24))));
}

__m128i sm4_round_aesni(__m128i block, __m128i rk) {
    __m128i t = _mm_xor_si128(block, rk);
    t = sm4_sbox_aesni(t);
    return sm4_linear(t);
}

void sm4_encrypt_aesni(const uint32_t* rk, const uint8_t* in, uint8_t* out) {
    __m128i state = _mm_loadu_si128((const __m128i*)in);

    // 反序加载
    state = _mm_shuffle_epi32(state, 0x1B);

    for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
        __m128i rk128 = _mm_set1_epi32(rk[i]);
        __m128i tmp = sm4_round_aesni(state, rk128);
        state = _mm_shuffle_epi32(state, 0x39); // 旋转状态
        state = _mm_insert_epi32(state, _mm_extract_epi32(tmp, 0), 3);
    }

    // 反序存储
    state = _mm_shuffle_epi32(state, 0x1B);
    _mm_storeu_si128((__m128i*)out, state);
}
#endif

// SM4-GCM实现 
typedef struct {
    uint32_t rk[SM4_NUM_ROUNDS];
    uint8_t key[16];
    uint8_t iv[12];
    uint64_t len_aad;
    uint64_t len_plain;
    uint8_t H[16];      // GHASH key
    uint8_t J0[16];     // Pre-counter block
} sm4_gcm_ctx;

void ghash_mul(uint8_t* x, const uint8_t* y) {
    __m128i X = _mm_loadu_si128((__m128i*)x);
    __m128i Y = _mm_loadu_si128((__m128i*)y);

    // 使用PCLMULQDQ进行GF(2^128)乘法
    __m128i H = _mm_loadu_si128((__m128i*)x);
    __m128i T = _mm_clmulepi64_si128(H, Y, 0x00);
    __m128i U = _mm_clmulepi64_si128(H, Y, 0x11);
    __m128i V = _mm_clmulepi64_si128(H, Y, 0x01);
    __m128i W = _mm_clmulepi64_si128(H, Y, 0x10);

    V = _mm_xor_si128(V, W);
    W = _mm_slli_si128(V, 8);
    V = _mm_srli_si128(V, 8);
    T = _mm_xor_si128(T, W);
    U = _mm_xor_si128(U, V);

    // 模约简
    __m128i R = _mm_set_epi32(0, 0, 0, 0x87);
    __m128i M = _mm_clmulepi64_si128(U, R, 0x00);
    U = _mm_srli_si128(U, 8);
    T = _mm_xor_si128(T, M);
    M = _mm_clmulepi64_si128(T, R, 0x10);
    T = _mm_srli_si128(T, 8);
    U = _mm_xor_si128(U, M);

    X = _mm_unpacklo_epi64(T, U);
    _mm_storeu_si128((__m128i*)x, X);
}

void sm4_gcm_init(sm4_gcm_ctx* ctx, const uint8_t* key, const uint8_t* iv, size_t iv_len) {
    // 设置密钥
    memcpy(ctx->key, key, 16);
    sm4_key_schedule(key, ctx->rk);

    // 计算H = SM4(0)
    uint8_t zero[16] = { 0 };
    sm4_encrypt(ctx->rk, zero, ctx->H);

    // 初始化长度计数器
    ctx->len_aad = 0;
    ctx->len_plain = 0;

    // 构造J0
    if (iv_len == 12) {
        memcpy(ctx->J0, iv, 12);
        ctx->J0[12] = 0;
        ctx->J0[13] = 0;
        ctx->J0[14] = 0;
        ctx->J0[15] = 1;
    }
    else {
        // GHASH处理IV
        memset(ctx->J0, 0, 16);
        size_t iv_blocks = (iv_len + 15) / 16;
        for (size_t i = 0; i < iv_blocks; i++) {
            uint8_t block[16] = { 0 };
            size_t len = (i == iv_blocks - 1) ? iv_len % 16 : 16;
            if (len == 0) len = 16;
            memcpy(block, iv + i * 16, len);
            ghash_mul(ctx->J0, block);
        }

        // 添加长度块
        uint8_t len_block[16];
        memset(len_block, 0, 16);
        STORE32U(len_block + 12, (uint32_t)(iv_len * 8));
        ghash_mul(ctx->J0, len_block);
    }
}

void sm4_gcm_aad(sm4_gcm_ctx* ctx, const uint8_t* aad, size_t len) {
    size_t blocks = len / 16;
    size_t rem = len % 16;

    for (size_t i = 0; i < blocks; i++) {
        ghash_mul(ctx->J0, aad + i * 16);
    }

    if (rem > 0) {
        uint8_t block[16] = { 0 };
        memcpy(block, aad + blocks * 16, rem);
        ghash_mul(ctx->J0, block);
    }

    ctx->len_aad += len;
}

void sm4_gcm_encrypt(sm4_gcm_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t counter[16];
    memcpy(counter, ctx->J0, 16);

    size_t blocks = len / 16;
    size_t rem = len % 16;

    for (size_t i = 0; i < blocks; i++) {
        // 增加计数器
        for (int j = 15; j >= 12; j--) {
            if (++counter[j] != 0) break;
        }

        // 加密计数器
        uint8_t keystream[16];
        sm4_encrypt(ctx->rk, counter, keystream);

        // 加密明文块
        for (int j = 0; j < 16; j++) {
            out[i * 16 + j] = in[i * 16 + j] ^ keystream[j];
        }

        // 更新GHASH
        ghash_mul(ctx->J0, out + i * 16);
    }

    // 处理剩余部分
    if (rem > 0) {
        for (int j = 15; j >= 12; j--) {
            if (++counter[j] != 0) break;
        }

        uint8_t keystream[16];
        sm4_encrypt(ctx->rk, counter, keystream);

        for (size_t j = 0; j < rem; j++) {
            out[blocks * 16 + j] = in[blocks * 16 + j] ^ keystream[j];
        }

        uint8_t block[16] = { 0 };
        memcpy(block, out + blocks * 16, rem);
        ghash_mul(ctx->J0, block);
    }

    ctx->len_plain += len;
}

void sm4_gcm_final(sm4_gcm_ctx* ctx, uint8_t* tag, size_t tag_len) {
    // 添加长度块
    uint8_t len_block[16];
    memset(len_block, 0, 16);
    STORE32U(len_block, (uint32_t)(ctx->len_aad * 8));
    STORE32U(len_block + 8, (uint32_t)(ctx->len_plain * 8));
    ghash_mul(ctx->J0, len_block);

    // 加密J0生成tag
    uint8_t tag_block[16];
    sm4_encrypt(ctx->rk, ctx->J0, tag_block);

    // 取前tag_len字节作为tag
    memcpy(tag, tag_block, tag_len);
}

// 测试函数 
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // 测试密钥和明文
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t plain[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t cipher[16];
    uint32_t rk[SM4_NUM_ROUNDS];

    // 基本实现测试
    sm4_key_schedule(key, rk);
    sm4_encrypt(rk, plain, cipher);
    print_hex("Basic SM4 cipher", cipher, 16);

    // T-table优化测试
    sm4_init_ttable();
    sm4_encrypt_ttable(rk, plain, cipher);
    print_hex("T-table SM4 cipher", cipher, 16);

    // AESNI优化测试
#ifdef __AES__
    sm4_encrypt_aesni(rk, plain, cipher);
    print_hex("AESNI SM4 cipher", cipher, 16);
#endif

    // SM4-GCM测试
    uint8_t iv[12] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b };
    uint8_t aad[20] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    uint8_t gcm_plain[32] = "Hello, SM4-GCM encryption!";
    uint8_t gcm_cipher[32];
    uint8_t tag[16];

    sm4_gcm_ctx ctx;
    sm4_gcm_init(&ctx, key, iv, 12);
    sm4_gcm_aad(&ctx, aad, sizeof(aad));
    sm4_gcm_encrypt(&ctx, gcm_plain, gcm_cipher, sizeof(gcm_plain));
    sm4_gcm_final(&ctx, tag, 16);

    print_hex("GCM cipher", gcm_cipher, sizeof(gcm_plain));
    print_hex("GCM tag", tag, 16);

    return 0;
}