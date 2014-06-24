void ramhog_gen_pad(const uint8_t *input, size_t input_size,
                    uint32_t C, uint32_t padIndex,
                    uint64_t *padOut);

void ramhog_run_iterations(const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size,
                           uint32_t N, uint32_t C, uint32_t I,
                           uint64_t **scratchpads);
        
void ramhog(const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size,
            uint32_t N, uint32_t C, uint32_t I, uint64_t **scratchpads);