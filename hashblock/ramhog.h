int ramhog_gen_pad(uint8_t thr_id, const uint8_t *input, size_t input_size,
                    uint32_t C, uint32_t padIndex,
                    uint64_t *padOut);

int ramhog_run_iterations(uint8_t thr_id, const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size,
                           uint32_t N, uint32_t C, uint32_t I,
                           uint64_t **scratchpads);