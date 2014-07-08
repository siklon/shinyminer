#define MAIN_SHINY_PADS 16
#define MAIN_SHINY_CHUNKS 125829120
#define MAIN_SHINY_ITERS 8388608

struct ramhog_pool
{
    uint32_t N, C, I;
    int numSimultaneous, numWorkers;
    uint64_t ***scratchpads;
};

struct ramhog_pool *ramhog_thread_pool(uint32_t Nin, uint32_t Cin, uint32_t Iin, int numSimultaneousIn, int numWorkersIn);

void ramhog_thread_pool_dispose(struct ramhog_pool *pool);

int scanhash_ramhog(int thr_id, uint32_t *pdata, uint32_t *ptarget, uint32_t *phash, uint32_t max_nonce, unsigned long *hashes_done);

bool ramhog_mt(int thr_id, struct ramhog_pool *pool, const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size);