#include "cpuminer-config.h"
#include "miner.h"

#include <memory.h>

#include "ramhog.h"
#include "pbkdf2.c"

typedef struct
{
    uint64_t s[64];
    uint8_t p;
    uint64_t last;
} xorshift_ctx;

static inline uint64_t xorshift_next(xorshift_ctx *pctx)
{
    uint64_t s0 = pctx->s[ pctx->p ];
    uint64_t s1 = pctx->s[ pctx->p = ( pctx->p + 1 ) & 63 ];
    s1 ^= s1 << 25; // a
    s1 ^= s1 >> 3;  // b
    s0 ^= s0 >> 49; // c
    pctx->s[ pctx->p ] = s0 ^ s1;
    return ( pctx->s[ pctx->p ] = s0 ^ s1 ) * 8372773778140471301LL;
}

static void xorshift_pbkdf2_seed(xorshift_ctx *ctx, const uint8_t *seed, size_t seedlen, const uint8_t *salt, size_t saltlen)
{
    uint64_t fullSeed[65];
    
    PBKDF2_SHA256(seed, seedlen, salt, saltlen, 128, (uint8_t *)fullSeed, sizeof(uint64_t)*65);
    
    memcpy(ctx->s, &fullSeed[0], sizeof(uint64_t)*64);
    ctx->p = (uint8_t)(fullSeed[16] & 63);
}

int ramhog_gen_pad(uint8_t thr_id, const uint8_t *input, size_t input_size,
                    uint32_t C, uint32_t padIndex,
                    uint64_t *padOut)
{
    xorshift_ctx ctx;
    uint32_t chunk;
    
    xorshift_pbkdf2_seed(&ctx, input, input_size, (uint8_t *)&padIndex, 4);
    
    padOut[0] = xorshift_next(&ctx);
    padOut[1] = xorshift_next(&ctx);
    
    for (chunk=2; chunk < C; chunk++)
    {
        if(work_restart[thr_id].restart == 1)
            return 1;
            
        padOut[chunk] = xorshift_next(&ctx);
        if (!(padOut[chunk] & 511))
            padOut[chunk] ^= padOut[xorshift_next(&ctx) % (chunk/2) + chunk/2];
    }
    return 0;
}

int ramhog_run_iterations(uint8_t thr_id, const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size,
                           uint32_t N, uint32_t C, uint32_t I,
                           uint64_t **scratchpads)
{
    xorshift_ctx ctx;
    uint32_t i, padIndex;
    uint64_t X;
    uint64_t finalChunks[N * 32];
    uint64_t finalSalt[32] = {N, C, I, input_size, output_size};
    
    if(work_restart[thr_id].restart == 1)
        return 1;
        
    for (padIndex=0; padIndex < N; padIndex++)
    {
        memcpy(&finalChunks[padIndex * 32], &scratchpads[padIndex][C - 1 - 32], sizeof(uint64_t) * 32);
    }
    
    xorshift_pbkdf2_seed(&ctx, input, input_size, (uint8_t *)&finalChunks[0], sizeof(uint64_t) * N);
    
    X = xorshift_next(&ctx);
    
    if(work_restart[thr_id].restart == 1)
        return 1;
    
    for (i=0; i < I - (32 - 5); i++)
    {
        X = scratchpads[(X & 0xffffffff00000000L) & (N - 1)][(X & 0x00000000ffffffffL) % C] ^ xorshift_next(&ctx);
        if(work_restart[thr_id].restart == 1)
            return 1;
    }
    
    for (i=5; i < 32; i++)
    {
        X = scratchpads[(X & 0xffffffff00000000L) & (N - 1)][(X & 0x00000000ffffffffL) % C] ^ xorshift_next(&ctx);
        finalSalt[i] = X;
        if(work_restart[thr_id].restart == 1)
            return 1;
    }
    
    PBKDF2_SHA256(input, input_size,
                  (uint8_t *)finalSalt, sizeof(uint64_t)*32,
                  1, (uint8_t *)output, output_size);
                  
    if(work_restart[thr_id].restart == 1)
        return 1;
        
    return 0;
}

