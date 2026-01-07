// TODO(geni): Documentation, clean up, sweep for consistency, fuzzing...

#ifndef SIMDSC_H
#define SIMDSC_H

/*===========================================================================*/
/* Architecture detection                                                    */
/*===========================================================================*/

#if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || defined(_M_X64) || defined(_M_AMD64) || \
    defined(_M_IX86) || defined(__i386__) || defined(__i686__)
#define SIMDSC_X86 1
#else
#error simdscanner only supports x86 architectures
#endif

#if defined(__i686__) || defined(__i386__) || defined(_M_IX86)
#define SIMDSC_I686 1
#else
#define SIMDSC_I686 0
#endif

/*===========================================================================*/
/* Compile-level SIMD capabilities                                           */
/*===========================================================================*/

#ifndef SIMDSC_AVX2
#ifdef __AVX2__
#define SIMDSC_AVX2 1
#else
#define SIMDSC_AVX2 0
#endif
#endif

#ifndef SIMDSC_SSE2
#if (defined(_M_AMD64) || defined(_M_X64)) || _M_IX86_FP == 2 || _M_IX86_FP == 1
#define SIMDSC_SSE2 1
#else
#define SIMDSC_SSE2 0
#endif
#endif

/*===========================================================================*/
/* User-configurable options                                                 */
/*===========================================================================*/

#ifndef SIMDSC_RUNTIME_DISPATCH
#define SIMDSC_RUNTIME_DISPATCH 0
#endif

#ifndef SIMDSC_RUNTIME_DISPATCH_THREAD_SAFE
#define SIMDSC_RUNTIME_DISPATCH_THREAD_SAFE 0
#endif

#ifndef SIMDSC_DEFAULT_ALLOC
#define SIMDSC_DEFAULT_ALLOC 0
#endif

#ifndef SIMDSC_EASY_MAX_SIGNATURE_SIZE
#define SIMDSC_EASY_MAX_SIGNATURE_SIZE 1024
#endif

#ifndef SIMDSC_STATIC
#define SIMDSC_STATIC 0
#endif

/*===========================================================================*/
/* Utility macros                                                            */
/*===========================================================================*/

#define SIMDSC_STATIC_ASSERT(e) typedef char __SIMDSC_STATIC_ASSERT__[(e) ? 1 : -1]

#if SIMDSC_STATIC
#define SIMDSC_PUBLIC_API static
#else
#define SIMDSC_PUBLIC_API extern
#endif

/*===========================================================================*/
/* Compile-time validation                                                   */
/*===========================================================================*/

#if SIMDSC_RUNTIME_DISPATCH_THREAD_SAFE && (!defined(__GNUC__) && !defined(__clang__) && !defined(_MSC_VER))
#error SIMDSC_RUNTIME_DISPATCH_THREAD_SAFE requires GCC, Clang, or MSVC
#endif
SIMDSC_STATIC_ASSERT((SIMDSC_EASY_MAX_SIGNATURE_SIZE & 31) == 0);

/*===========================================================================*/
/* Includes                                                           */
/*===========================================================================*/

#ifdef SIMDSC_SYSTEM_HEADER
#include SIMDSC_SYSTEM_HEADER
#else
#include <stdint.h>
#endif

#ifdef _MSC_VER
#include <intrin.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================*/
/* Types                                                                     */
/*===========================================================================*/
typedef uint64_t simdsc_u64;
typedef uint8_t  simdsc_u8;
typedef uint16_t simdsc_u16;
typedef uint32_t simdsc_u32;
typedef int32_t  simdsc_i32;
enum {
    SIMDSC_RESULT_INVALID_HEX_CHAR    = -7,
    SIMDSC_RESULT_EMPTY_SIGNATURE     = -6,
    SIMDSC_RESULT_UNALIGNED_BUFFER    = -5,
    SIMDSC_RESULT_ALLOC_FAILED        = -4,
    SIMDSC_RESULT_INVALID_PARAMETER   = -3,
    SIMDSC_RESULT_UNDERSIZED_BUFFER   = -2,
    SIMDSC_RESULT_MALFORMED_SIGNATURE = -1,
    SIMDSC_RESULT_SUCCESS             = 0,
    SIMDSC_RESULT_NOT_FOUND           = 1,
};
typedef int32_t simdsc_result;

typedef struct simdsc_string8 {
    union {
        simdsc_u8* s;
        simdsc_u8* str;
        char*      cstr;
        void*      data;
    };
    simdsc_u64 size;
} simdsc_string8;

#define SIMDSC_S8LIT(s) (simdsc_string8) SIMDSC_S8LIT_COMP(s)
#define SIMDSC_S8LIT_COMP(s) \
    {(simdsc_u8*) (s), sizeof(s) - 1}

typedef void* (*simdsc_alloc_fn)(void* ctx, simdsc_u64 size);

/*===========================================================================*/
/* Functions                                                                 */
/*===========================================================================*/

SIMDSC_PUBLIC_API simdsc_result simdsc_compile_signature(const simdsc_string8 signature, simdsc_u8* compiled_out, simdsc_u64 compiled_out_size, simdsc_u8* mask_out, simdsc_u64 mask_out_size, simdsc_u64* out_offset);
SIMDSC_PUBLIC_API simdsc_result simdsc_scalar_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u8* pattern, simdsc_u64 pattern_size, simdsc_u64* out_offset);
SIMDSC_PUBLIC_API simdsc_result simdsc_auto_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u64 mask_buf_size, simdsc_u8* pattern, simdsc_u64 pattern_buf_size, simdsc_u64 pattern_size, simdsc_u64* out_offset);

#if SIMDSC_AVX2
SIMDSC_PUBLIC_API simdsc_result simdsc_avx2_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u64 mask_buf_size, simdsc_u8* pattern, simdsc_u64 pattern_buf_size, simdsc_u64 pattern_size, simdsc_u64* out_offset);
#endif

#if SIMDSC_SSE2
SIMDSC_PUBLIC_API simdsc_result simdsc_sse2_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u64 mask_buf_size, simdsc_u8* pattern, simdsc_u64 pattern_buf_size, simdsc_u64 pattern_size, simdsc_u64* out_offset);
#endif

SIMDSC_PUBLIC_API simdsc_result simdsc_easy_find(const simdsc_u8* data, simdsc_u64 data_size, simdsc_string8 signature, simdsc_u64* out_offset);

SIMDSC_PUBLIC_API simdsc_result simdsc_alloc_signature(simdsc_string8 signature, simdsc_u8** compiled_out, simdsc_u8** mask_out, simdsc_u64* out_size, simdsc_alloc_fn alloc_fn, void* alloc_ctx);

#if SIMDSC_DEFAULT_ALLOC
SIMDSC_PUBLIC_API void*         simdsc_default_alloc(void* ctx, simdsc_u64 size);
SIMDSC_PUBLIC_API void          simdsc_default_free(void* ptr);
SIMDSC_PUBLIC_API simdsc_result simdsc_alloc_signature_default(simdsc_string8 signature, simdsc_u8** compiled_out, simdsc_u8** mask_out, simdsc_u64* out_size);
#endif

SIMDSC_PUBLIC_API simdsc_string8 simdsc_string8_from_cstr(const char* cstr);

#if SIMDSC_RUNTIME_DISPATCH
typedef struct simdsc_simd_support {
    simdsc_u32 sse2;
    simdsc_u32 avx2;
} simdsc_simd_support;
SIMDSC_PUBLIC_API simdsc_simd_support simdsc_cpu_capabilities(void);
#endif

/*===========================================================================*/
/* Implementation                                                            */
/*===========================================================================*/

#ifdef SIMDSC_IMPLEMENTATION

#include <string.h>

#if SIMDSC_SSE2
#include <emmintrin.h>
#endif

#if SIMDSC_AVX2
#include <immintrin.h>
#endif

#define SIMDSC_STRLEN(s) ((simdsc_u32) strlen(s))

#ifdef SIMDSC_DEFAULT_ALLOC
#include <stdlib.h>
#ifdef _MSC_VER
#include <malloc.h>
void* simdsc_default_alloc(void* ctx, simdsc_u64 size) {
    (void) ctx;
    void* ptr = _aligned_malloc(size, 32);
    if (ptr == NULL) {
        ptr = malloc(size);
    }
    return ptr;
}
void simdsc_default_free(void* ptr) {
    _aligned_free(ptr);
}
#else
void* simdsc_default_alloc(void* ctx, simdsc_u64 size) {
    (void) ctx;
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || (defined(__cplusplus) && __cplusplus >= 201703L)
    void* ptr = aligned_alloc(32, size);
    if (ptr == NULL) {
        ptr = malloc(size);
    }
#else
    void* ptr = malloc(size);
#endif
    return ptr;
}
void simdsc_default_free(void* ptr) {
    free(ptr);
}
#endif  // _MSC_VER
#endif  // SIMDSC_DEFAULT_ALLOC

#if defined(_MSC_VER) && !defined(__clang__)
#define SIMDSC_TARGET(arch)
#else
#define SIMDSC_TARGET(arch) __attribute__((target(arch)))
#endif

#if SIMDSC_RUNTIME_DISPATCH

#if SIMDSC_X86
typedef struct simdsc_cpuid_regs {
    simdsc_u32 eax;
    simdsc_u32 ebx;
    simdsc_u32 ecx;
    simdsc_u32 edx;
} simdsc_cpuid_regs;
SIMDSC_STATIC_ASSERT(sizeof(simdsc_cpuid_regs) == sizeof(int[4]));
#endif  // SIMDSC_X86

#endif  // SIMDSC_RUNTIME_DISPATCH

#if defined(_MSC_VER) && !defined(__clang__)
static __inline uint32_t simdsc_ctz(uint32_t value) {
    unsigned long trailing_zero = 0;

    if (_BitScanForward(&trailing_zero, value)) {
        return trailing_zero;
    } else {
        // NOTE(geni): Undefined behavior if value is 0 :^)
        return 0;
    }
}
#else
#define simdsc_ctz __builtin_ctz
#endif  // defined(_MSC_VER) && !defined(__clang__)

simdsc_string8 simdsc_string8_from_cstr(const char* str) {
    simdsc_string8 result;
    result.cstr = (char*) str;
    result.size = SIMDSC_STRLEN(str);
    return result;
}

static inline simdsc_i32 simdsc_hex_char_to_nibble(simdsc_u8 c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// NOTE(geni): Returns 0 on success, -1 on invalid hex character
static inline simdsc_i32 simdsc_hexpair_to_u8(simdsc_u8* data, simdsc_u8* out) {
    simdsc_i32 hi = simdsc_hex_char_to_nibble(data[0]);
    simdsc_i32 lo = simdsc_hex_char_to_nibble(data[1]);
    if (hi < 0 || lo < 0) {
        return -1;
    }
    *out = (simdsc_u8) ((hi << 4) | lo);
    return 0;
}

simdsc_result simdsc_compile_signature(const simdsc_string8 signature, simdsc_u8* compiled_out, simdsc_u64 compiled_out_size, simdsc_u8* mask_out, simdsc_u64 mask_out_size, simdsc_u64* out_size) {
    if (signature.s == NULL || compiled_out == NULL || mask_out == NULL || out_size == NULL) {
        return SIMDSC_RESULT_INVALID_PARAMETER;
    }

    simdsc_u8* cur = signature.s;
    simdsc_u8* end = signature.s + signature.size;

    simdsc_u64 i = 0;
    while (cur != end) {
        if (i >= mask_out_size || i >= compiled_out_size) {
            *out_size = 0;
            return SIMDSC_RESULT_UNDERSIZED_BUFFER;
        }

        // NOTE(geni): Skip spaces
        if (*cur == ' ') {
            ++cur;
            continue;
        }

        // NOTE(geni): Handle wildcards
        if (*cur == '?') {
            mask_out[i]     = 0;
            compiled_out[i] = 0;
            ++i;
            ++cur;

            if (cur < end && *cur == '?') {
                ++cur;
            }
            continue;
        }

        // NOTE(geni): Malformed pattern check
        if (cur + 1 >= end) {
            *out_size = 0;
            return SIMDSC_RESULT_MALFORMED_SIGNATURE;
        }

        // NOTE(geni): Handle bytes
        simdsc_u8 byte;
        if (simdsc_hexpair_to_u8(cur, &byte) < 0) {
            *out_size = 0;
            return SIMDSC_RESULT_INVALID_HEX_CHAR;
        }
        mask_out[i]     = 0xFF;
        compiled_out[i] = byte;

        cur += 2;
        ++i;
    }

    // NOTE(geni): Empty signature check
    if (i == 0) {
        *out_size = 0;
        return SIMDSC_RESULT_EMPTY_SIGNATURE;
    }

    *out_size = i;
    return SIMDSC_RESULT_SUCCESS;
}

simdsc_result simdsc_scalar_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u8* pattern, simdsc_u64 pattern_size, simdsc_u64* out_offset) {
    if (data == NULL || mask == NULL || pattern == NULL || out_offset == NULL || pattern_size == 0) {
        return SIMDSC_RESULT_INVALID_PARAMETER;
    }

    if (data_size < pattern_size) {
        return SIMDSC_RESULT_NOT_FOUND;
    }

    for (simdsc_u64 i = 0; i <= data_size - pattern_size; ++i) {
        if (data[i] != pattern[0] && mask[0] == 0xFF) {
            continue;
        }
        if (data[i + pattern_size - 1] != pattern[pattern_size - 1] && mask[pattern_size - 1] == 0xFF) {
            continue;
        }
        for (simdsc_u32 j = 0; j < pattern_size; ++j) {
            if ((data[i + j] & mask[j]) != pattern[j]) {
                goto again;
            }
        }

        *out_offset = i;
        return SIMDSC_RESULT_SUCCESS;
    again:;
    }

    *out_offset = 0;
    return SIMDSC_RESULT_NOT_FOUND;
}

#if SIMDSC_AVX2
SIMDSC_TARGET("avx2,bmi") simdsc_result simdsc_avx2_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u64 mask_buf_size, simdsc_u8* pattern, simdsc_u64 pattern_buf_size, simdsc_u64 pattern_size, simdsc_u64* out_offset) {
    if (data == NULL || mask == NULL || pattern == NULL || out_offset == NULL || pattern_size == 0) {
        return SIMDSC_RESULT_INVALID_PARAMETER;
    }

    if ((mask_buf_size & 31) != 0 || (pattern_buf_size & 31) != 0) {
        return SIMDSC_RESULT_UNALIGNED_BUFFER;
    }

    if (data_size < pattern_size) {
        return SIMDSC_RESULT_NOT_FOUND;
    }

    const __m256i first_pattern_byte = _mm256_set1_epi8(pattern[0] & mask[0]);
    const __m256i last_pattern_byte  = _mm256_set1_epi8(pattern[pattern_size - 1] & mask[pattern_size - 1]);

    const __m256i first_mask_byte = _mm256_set1_epi8(mask[0]);
    const __m256i last_mask_byte  = _mm256_set1_epi8(mask[pattern_size - 1]);

    simdsc_u64 i = 0;
    if (data_size >= pattern_size + 32) {
        for (; i < data_size - pattern_size - 32; i += 32) {
            __m256i chunk_first = _mm256_loadu_si256((__m256i*) (data + i));
            __m256i chunk_last  = _mm256_loadu_si256((__m256i*) (data + i + pattern_size - 1));
            chunk_first         = _mm256_and_si256(chunk_first, first_mask_byte);
            chunk_last          = _mm256_and_si256(chunk_last, last_mask_byte);

            __m256i cmp = _mm256_cmpeq_epi8(chunk_first, first_pattern_byte);
            // NOTE(geni): Only match if BOTH first and last bytes match.
            cmp = _mm256_and_si256(cmp, _mm256_cmpeq_epi8(chunk_last, last_pattern_byte));

            simdsc_u32 matches = _mm256_movemask_epi8(cmp);
            // NOTE(geni): Try all matches
            while (matches != 0) {
                // NOTE(geni): Find first matching byte
                simdsc_u32 local_offset = simdsc_ctz(matches);
                simdsc_u64 offset       = i + local_offset;

                for (simdsc_u32 j = 0; j < pattern_size; j += 32) {
                    __m256i chunk = _mm256_loadu_si256((__m256i*) (data + offset + j));

                    __m256i pattern_data = _mm256_loadu_si256((__m256i*) (pattern + j));
                    __m256i mask_data    = _mm256_loadu_si256((__m256i*) (mask + j));

                    __m256i match = _mm256_xor_si256(chunk, pattern_data);
                    if (!_mm256_testz_si256(match, mask_data)) {
                        goto again;
                    }
                }

                *out_offset = offset;
                return SIMDSC_RESULT_SUCCESS;
            again:
                // NOTE(geni): Clear match
                matches = _blsr_u32(matches);
            }
        }
    }

    // NOTE(geni): Fall back to scalar method for last bytes
    if (i <= data_size - pattern_size) {
        simdsc_u64 offset;
        if (simdsc_scalar_pattern_match(data + i, data_size - i, mask, pattern, pattern_size, &offset) != SIMDSC_RESULT_NOT_FOUND) {
            *out_offset = i + offset;
            return SIMDSC_RESULT_SUCCESS;
        }
    }

    *out_offset = 0;
    return SIMDSC_RESULT_NOT_FOUND;
}
#endif  // SIMDSC_AVX2

#if SIMDSC_SSE2
SIMDSC_TARGET("sse2") simdsc_result simdsc_sse2_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u64 mask_buf_size, simdsc_u8* pattern, simdsc_u64 pattern_buf_size, simdsc_u64 pattern_size, simdsc_u64* out_offset) {
    if (data == NULL || mask == NULL || pattern == NULL || out_offset == NULL || pattern_size == 0) {
        return SIMDSC_RESULT_INVALID_PARAMETER;
    }

    if ((mask_buf_size & 15) != 0 || (pattern_buf_size & 15) != 0) {
        return SIMDSC_RESULT_UNALIGNED_BUFFER;
    }

    if (data_size < pattern_size) {
        return SIMDSC_RESULT_NOT_FOUND;
    }

    const __m128i first_pattern_byte = _mm_set1_epi8(pattern[0] & mask[0]);
    const __m128i last_pattern_byte  = _mm_set1_epi8(pattern[pattern_size - 1] & mask[pattern_size - 1]);

    const __m128i first_mask_byte = _mm_set1_epi8(mask[0]);
    const __m128i last_mask_byte  = _mm_set1_epi8(mask[pattern_size - 1]);

    simdsc_u64 i = 0;
    if (data_size >= pattern_size + 16) {
        for (; i < data_size - pattern_size - 16; i += 16) {
            __m128i chunk_first = _mm_loadu_si128((__m128i*) (data + i));
            __m128i chunk_last  = _mm_loadu_si128((__m128i*) (data + i + pattern_size - 1));
            chunk_first         = _mm_and_si128(chunk_first, first_mask_byte);
            chunk_last          = _mm_and_si128(chunk_last, last_mask_byte);

            __m128i cmp = _mm_cmpeq_epi8(chunk_first, first_pattern_byte);
            // NOTE(geni): Only match if BOTH first and last bytes match
            cmp = _mm_and_si128(cmp, _mm_cmpeq_epi8(chunk_last, last_pattern_byte));

            simdsc_u32 matches = _mm_movemask_epi8(cmp);
            // NOTE(geni): Try all matches
            while (matches != 0) {
                simdsc_u32 local_offset = simdsc_ctz(matches);
                simdsc_u64 offset       = i + local_offset;

                for (simdsc_u64 j = 0; j < pattern_size; j += 16) {
                    __m128i chunk = _mm_loadu_si128((__m128i*) (data + offset + j));

                    __m128i pattern_data = _mm_loadu_si128((__m128i*) (pattern + j));
                    __m128i mask_data    = _mm_loadu_si128((__m128i*) (mask + j));

                    __m128i match = _mm_and_si128(chunk, mask_data);
                    match         = _mm_cmpeq_epi8(match, pattern_data);

                    if (_mm_movemask_epi8(match) != 0xFFFF) {
                        goto again;
                    }
                }

                *out_offset = offset;
                return SIMDSC_RESULT_SUCCESS;
            again:
                // NOTE(geni): Clear match
                matches &= matches - 1;
            }
        }
    }

    // NOTE(geni): Fall back to scalar method for last bytes
    if (i <= data_size - pattern_size) {
        simdsc_u64 offset;
        if (simdsc_scalar_pattern_match(data + i, data_size - i, mask, pattern, pattern_size, &offset) != SIMDSC_RESULT_NOT_FOUND) {
            *out_offset = i + offset;
            return SIMDSC_RESULT_SUCCESS;
        }
    }

    *out_offset = 0;
    return SIMDSC_RESULT_NOT_FOUND;
}
#endif  // SIMDSC_SSE2

#if SIMDSC_RUNTIME_DISPATCH

#if SIMDSC_X86
static simdsc_simd_support simdsc_check_cpu_flags(void) {
    simdsc_simd_support result = {0};

#if SIMDSC_SSE2
    simdsc_cpuid_regs regs_leaf1 = {0};
    // NOTE(geni): Check CPUID flags
#ifdef _MSC_VER
    __cpuidex((int*) &regs_leaf1, 1, 0);
#else
// NOTE(geni): Don't clobber EBX on 32-bit and PIC
#if SIMDSC_I686 && defined(__PIC__)
    __asm__ __volatile__(
        "pushl %%ebx\n\t"
        "cpuid\n\t"
        "movl %%ebx, %1\n\t"
        "popl %%ebx"
        : "=a"(regs_leaf1.eax), "=r"(regs_leaf1.ebx), "=c"(regs_leaf1.ecx), "=d"(regs_leaf1.edx)
        : "a"(1), "c"(0));
#else
    __asm__ __volatile__("cpuid"
                         : "=a"(regs_leaf1.eax), "=b"(regs_leaf1.ebx), "=c"(regs_leaf1.ecx), "=d"(regs_leaf1.edx)
                         : "a"(1), "c"(0));
#endif  // SIMDSC_I686 && defined(__PIC__)
#endif  // _MSC_VER
    result.sse2 = (regs_leaf1.edx & 0x04000000) != 0;
#endif  // SIMDSC_SSE2

#if SIMDSC_AVX2
    simdsc_cpuid_regs regs_leaf7 = {0};
    // NOTE(geni): Check CPUID flags
#ifdef _MSC_VER
    __cpuidex((int*) &regs_leaf7, 7, 0);
#else
    __asm__ __volatile__("cpuid"
                         : "=a"(regs_leaf7.eax), "=b"(regs_leaf7.ebx), "=c"(regs_leaf7.ecx), "=d"(regs_leaf7.edx)
                         : "a"(7), "c"(0));
#endif  // _MSC_VER
    result.avx2 = (regs_leaf7.ebx & 0x00000020) != 0;

    // NOTE(geni): Check if OS is sane
    simdsc_u32 xcr0;
#if defined(_MSC_VER)
    xcr0 = (uint32_t) _xgetbv(0);
#else
    __asm__("xgetbv" : "=a"(xcr0) : "c"(0) : "%edx");
#endif  // defined(_MSC_VER)
    result.avx2 &= (xcr0 & 6) == 6;
#endif  // SIMDSC_AVX2

    return result;
}
#endif  // SIMDSC_X86

simdsc_simd_support simdsc_cpu_capabilities(void) {
    static simdsc_simd_support info;

#if SIMDSC_RUNTIME_DISPATCH_THREAD_SAFE
    static volatile simdsc_u32 initialized = 0;

#if defined(__GNUC__) || defined(__clang__)
    if (__sync_val_compare_and_swap(&initialized, 1, 1)) {
        return info;
    }
#elif defined(_MSC_VER)
    if (_InterlockedExchangeAdd((long volatile*) &initialized, 0)) {
        return info;
    }
#endif  // defined(__GNUC__) || defined(__clang__)

    info = simdsc_check_cpu_flags();

#if defined(__GNUC__) || defined(__clang__)
    __sync_synchronize();
    initialized = 1;
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
    initialized = 1;
#else
    initialized = 1;
#endif  // defined(__GNUC__) || defined(__clang__)

#else
    static simdsc_u32 initialized = 0;
    if (initialized) {
        return info;
    }

#if SIMDSC_X86
    info = simdsc_check_cpu_flags();
#endif  // SIMDSC_X86
    initialized = 1;
#endif  // SIMDSC_RUNTIME_DISPATCH_THREAD_SAFE

    return info;
}

#if SIMDSC_RUNTIME_DISPATCH
simdsc_result simdsc_auto_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u64 mask_buf_size, simdsc_u8* pattern, simdsc_u64 pattern_buf_size, simdsc_u64 pattern_size, simdsc_u64* out_offset) {
    simdsc_simd_support info = simdsc_cpu_capabilities();

#if SIMDSC_AVX2
    if (info.avx2) {
        return simdsc_avx2_pattern_match(data, data_size, mask, mask_buf_size, pattern, pattern_buf_size, pattern_size, out_offset);
    }
#endif  // SIMDSC_AVX2

#if SIMDSC_SSE2
    if (info.sse2) {
        return simdsc_sse2_pattern_match(data, data_size, mask, mask_buf_size, pattern, pattern_buf_size, pattern_size, out_offset);
    }
#endif  // SIMDSC_SSE2

    return simdsc_scalar_pattern_match(data, data_size, mask, pattern, pattern_size, out_offset);
}
#endif  // SIMDSC_RUNTIME_DISPATCH

#else

simdsc_result simdsc_auto_pattern_match(const simdsc_u8* data, const simdsc_u64 data_size, simdsc_u8* mask, simdsc_u64 mask_buf_size, simdsc_u8* pattern, simdsc_u64 pattern_buf_size, simdsc_u64 pattern_size, simdsc_u64* out_offset) {
#if SIMDSC_AVX2
    return simdsc_avx2_pattern_match(data, data_size, mask, mask_buf_size, pattern, pattern_buf_size, pattern_size, out_offset);
#elif SIMDSC_SSE2
    return simdsc_sse2_pattern_match(data, data_size, mask, mask_buf_size, pattern, pattern_buf_size, pattern_size, out_offset);
#else
    (void) mask_buf_size;
    (void) pattern_buf_size;
    return simdsc_scalar_pattern_match(data, data_size, mask, pattern, pattern_size, out_offset);
#endif  // SIMDSC_AVX2
}

#endif  // SIMDSC_RUNTIME_DISPATCH

static inline simdsc_u64 simdsc_round_up_32(simdsc_u64 size) {
    return (size + 31) & ~((simdsc_u64) 31);
}

simdsc_result simdsc_easy_find(const simdsc_u8* data, simdsc_u64 data_size, simdsc_string8 signature, simdsc_u64* out_offset) {
    if (data == NULL || signature.s == NULL || out_offset == NULL) {
        return SIMDSC_RESULT_INVALID_PARAMETER;
    }

    simdsc_u8  compiled_buf[SIMDSC_EASY_MAX_SIGNATURE_SIZE] = {0};
    simdsc_u8  mask_buf[SIMDSC_EASY_MAX_SIGNATURE_SIZE]     = {0};
    simdsc_u64 pattern_size;

    simdsc_result res = simdsc_compile_signature(signature, compiled_buf, sizeof compiled_buf, mask_buf, sizeof mask_buf, &pattern_size);
    if (res != SIMDSC_RESULT_SUCCESS) {
        return res;
    }

    return simdsc_auto_pattern_match(data, data_size, mask_buf, sizeof mask_buf, compiled_buf, sizeof compiled_buf, pattern_size, out_offset);
}

simdsc_result simdsc_alloc_signature(simdsc_string8 signature, simdsc_u8** compiled_out, simdsc_u8** mask_out, simdsc_u64* out_size, simdsc_alloc_fn alloc_fn, void* alloc_ctx) {
    if (signature.s == NULL || compiled_out == NULL || mask_out == NULL || out_size == NULL || alloc_fn == NULL) {
        return SIMDSC_RESULT_INVALID_PARAMETER;
    }

    simdsc_u64 buf_size = simdsc_round_up_32(signature.size / 2 + 1);
    if (buf_size < 32) buf_size = 32;

    *compiled_out = (simdsc_u8*) alloc_fn(alloc_ctx, buf_size);
    if (*compiled_out == NULL) {
        return SIMDSC_RESULT_ALLOC_FAILED;
    }
    memset(*compiled_out, 0, buf_size);

    *mask_out = (simdsc_u8*) alloc_fn(alloc_ctx, buf_size);
    if (*mask_out == NULL) {
        return SIMDSC_RESULT_ALLOC_FAILED;
    }
    memset(*mask_out, 0, buf_size);

    simdsc_result res = simdsc_compile_signature(signature, *compiled_out, buf_size, *mask_out, buf_size, out_size);
    return res;
}

#ifdef SIMDSC_DEFAULT_ALLOC
simdsc_result simdsc_alloc_signature_default(simdsc_string8 signature, simdsc_u8** compiled_out, simdsc_u8** mask_out, simdsc_u64* out_size) {
    return simdsc_alloc_signature(signature, compiled_out, mask_out, out_size, simdsc_default_alloc, NULL);
}
#endif  // SIMDSC_DEFAULT_ALLOC

#endif  // SIMDSC_IMPLEMENTATION

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SIMDSC_H
