# simdscanner

Fast signature scanner for x86-64 and x86 using SIMD instructions.

See the accompanying blog post: https://geni.site/simd-signature-scanner

> [!WARNING]
> The public API is unstable and subject to change without notice.

## Features
- AVX2 and SSE2 variants
- Support for both 32-bit and 64-bit targets
- Optional runtime dispatch for SSE2 and AVX2
- Support for custom allocators
- `easy_` API with no hidden allocations
- Optional default `_aligned_malloc` and `aligned_alloc`-based allocator

## Roadmap to 1.0
- [ ] **Documentation**
- [ ] **Testing**

## Planned features
- ARM NEON support
