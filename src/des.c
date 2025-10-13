/**
 * @file    des.c
 * @brief   Implementation of the Data Encryption Standard (DES) algorithm.
 *
 * @author  Hugo Sánchez
 * @date    2025-10-08
 * @version 1.0
 *
 * @details
 * This code provides a full implementation of the DES symmetric-key block cipher,
 * following the specification from the NST FIPS PUB 46-3:
 * https://csrc.nist.gov/pubs/fips/46-3/final
 *
 * The implementation follows the standard DES specification and is suitable
 * for educational purposes, experimentation, or integration into larger cryptographic
 * projects.  
 *
 * @note
 * All functions assume proper input ranges and are designed for educational purposes.
 *
 * @copyright
 * MIT License
 */

#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// #define DEBUG

#ifdef DEBUG
#define DPRINT(...) fprintf( stdout, __VA_ARGS__ )
#else
#define DPRINT(...) do { } while ( 0 )
#endif

// Initial permutation (IP)
const unsigned int init_perm[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

// Inverse/final permutation (IP^-1)
const unsigned int inv_perm[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25};
    
// Expansion table E (32 bits -> 48 bits)
const unsigned int exp_table[48] = {
    32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
    
// P permutation
const unsigned int P_perm[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23,
                                 26, 5, 18, 31, 10, 2,  8,  24, 14, 32, 27,
                                 3,  9, 19, 13, 30, 6,  22, 11, 4,  25};

// Permuted choice 1 (PC-1)
const unsigned int permuted_choice_1[56] = {
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
    35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
    46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};

// Permuted choice 1 (PC-2)
const unsigned int permuted_choice_2[48] = {
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
    26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

// S-boxes
const uint8_t S_BOX[8][4][16] = {
    { // S1
     {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
    { // S2
     {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
    { // S3
     {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
    { // S4
     {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
    { // S5
     {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
    { // S6
     {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
    { // S7
     {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
    { // S8
     {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};

// Bits Rotation
const unsigned int rotation_table[16] = {1, 1, 2, 2, 2, 2, 2, 2,
                                         1, 2, 2, 2, 2, 2, 2, 1};

char *to_binary_str(uint64_t value, int len) {

    char *out = malloc(len + 1);

    for (int i = 0; i < len; i++) {
        out[i] = ((value >> (len - 1 - i)) & 1) ? '1' : '0';
    }

    out[len] = '\0';
    return out;
}

void left_rotate(uint32_t *C, uint32_t *D, int shift, int bits) {
    uint32_t MASK = (1u << bits) - 1;

    *C = ((*C << shift) | (*C >> (bits - shift))) & MASK;
    *D = ((*D << shift) | (*D >> (bits - shift))) & MASK;
}

uint64_t permute_bits(const uint64_t input, const unsigned int *table,
                      int in_size, int out_size) {
    unsigned int bit_pos;
    uint64_t bit;
    uint64_t output = 0;

    for (int i = 0; i < out_size; i++) {
        // convert 1-based position to 0-based index
        bit_pos = in_size - table[i];

        // extract bit
        bit = (input >> bit_pos) & 0x1;

        // insert bit in output
        output <<= 1;
        output |= bit;
    }

    return output;
}

void split_key_halves(const uint64_t key, uint32_t *C, uint32_t *D, int half_bits) {
    uint64_t MASK = (1ULL << half_bits) - 1; // 1ULL: unsigned long long

    *C = (key >> half_bits) & MASK;
    *D = key & MASK;
}

void gen_subkeys(uint64_t key, uint64_t subkeys[16]) {

    uint64_t K_pc1 = permute_bits(key, permuted_choice_1, 64, 56);

    uint32_t C_0, D_0;
    split_key_halves(K_pc1, &C_0, &D_0, 28);

    uint32_t C[16] = {0}, D[16] = {0};
    C[0] = C_0; 
    D[0] = D_0;

    for (size_t i = 0; i < 16; ++i) {
        if (i > 0) {
            C[i] = C[i - 1];
            D[i] = D[i - 1];
        }
        left_rotate(&C[i], &D[i], rotation_table[i], 28);
    }

    for (size_t i = 0; i < 16; ++i) {
        uint64_t C_mask = ((uint64_t)C[i]) & 0x0FFFFFFF;
        uint64_t D_mask = ((uint64_t)D[i]) & 0x0FFFFFFF;
        uint64_t CD = (C_mask << 28) | D_mask;
        subkeys[i] = permute_bits(CD, permuted_choice_2, 56, 48);
    }
}

uint32_t sboxes_substitution(const uint64_t input) {
    int shift;
    uint8_t chunk, row, col, sval;
    uint32_t output = 0;
    
    for (int i = 0; i < 8; ++i) {
        // extract 6 bits chunk
        shift = 48 - 6 * (i + 1);
        chunk = (input >> shift) & 0x3F;  // 6 bits

        row = ((chunk & 0x20) >> 4) | (chunk & 0x01);  // b0 and b5 -> row (2 bits)
        col = (chunk >> 1) & 0x0F;         // middle 4 bits

        sval = S_BOX[i][row][col] & 0x0F;

        output = (output << 4) | sval;
    }
    return output;
}

uint64_t feistel(const uint64_t input, const uint64_t key) {
    uint64_t E_R, x, S, P;

    // expand (32 -> 48 bits)
    E_R = permute_bits((uint64_t) input, exp_table, 32, 48);

    // K_1 ^ E(R_0)
    x = E_R ^ (key & 0xFFFFFFFFFFFF);

    // S(K_1 ^ E(R_0))
    S = sboxes_substitution(x);

    // f = P(S(K_1 ^ E(R_0)))
    P = permute_bits((uint64_t) S, P_perm, 32, 32);

    return P;
}

/**
 * @brief Run the DES (Data Encryption Standard) algorithm on a 64-bit plaintext block.
 *
 * This function performs DES encryption on a 64-bit input block using a provided
 * 64-bit key and its corresponding 16 generated subkeys. It follows the standard
 * DES procedure, including the initial permutation, 16 Feistel rounds, and the final
 * inverse permutation to produce a 64-bit ciphertext.
 *
 * @param M        The 64-bit plaintext block to be encrypted.
 * @param K        The 64-bit key used to generate the subkeys.
 * @param subkeys  Pointer to an array of 16 64-bit subkeys.
 *
 * @return The 64-bit ciphertext resulting from the DES encryption of the plaintext block.
 *
 * @note This function assumes that both the plaintext message and the key are 64-bit long,
 * and that the subkeys have been precomputed using the DES key schedule algorithm.
 *
 * @details
 * Steps performed:
 *  - Applies the initial permutation (IP) to the plaintext.
 *  - Splits the permuted block into two 32-bit halves (L and R).
 *  - Executes 16 Feistel rounds, where each round computes:
 *        L[i] = R[i - 1]
 *        R[i] = L[i - 1] XOR f(R[i - 1], K[i])
 *  - After 16 rounds, concatenates R[15] and L[15] (note the swap).
 *  - Applies the final (inverse) permutation (IP⁻¹) to get the ciphertext.
 */
uint64_t des(const uint64_t M, const uint64_t K, const uint64_t *subkeys) {
    // encode data
    // initial permutation of M
    uint64_t IP = permute_bits(M, init_perm, 64, 64);

    DPRINT("M after IP = %s\n", to_binary_str(IP, 64));

    // split IP (64 bits -> 2 x 32 bits)
    uint32_t L_0, R_0;
    split_key_halves(IP, &L_0, &R_0, 32);

    // f(R_0, K_1) = R_0 XOR K_1
    uint32_t L[16] = {0}, R[16] = {0};

    L[0] = R_0;                                                      // L_1
    R[0] = L_0 ^ (uint32_t)(feistel(R_0, subkeys[0]) & 0xFFFFFFFF);  // R_1


    for (size_t i = 1; i < 16; ++i) {
        L[i] = R[i - 1];  // L_i
        R[i] = L[i - 1] ^ (uint32_t)(feistel(R[i - 1], subkeys[i]) & 0xFFFFFFFF);  // R_i
    }

    uint64_t RL = ((uint64_t) R[15] << 32) | (uint64_t)L[15];
    uint64_t RL_inv = permute_bits(RL, inv_perm, 64, 64);

    return RL_inv;
}

int main(int argc, char **argv) {
    int opt, encrypt = -1;
    optind = 1;

    uint64_t key, msg;

    while ((opt = getopt(argc, argv, "edk:m:h")) != -1) {
        switch (opt) {
            case 'e': encrypt = 1; break;
            case 'd': encrypt = 0; break;
            case 'k': key = strtoull(optarg, NULL, 16); break;
            case 'm': msg = strtoull(optarg, NULL, 16); break;
            case 'h':
            default:
                fprintf(stderr, "Use: %s -e|-d -k KEY_HEX -m MESSAGE\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (encrypt == -1 || !key || !msg) {
        fprintf(stderr, "Missing arguments. Use: %s -e|-d -k KEY_HEX -m MESSAGE\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const uint64_t M = msg;
    const uint64_t K = key;
    uint64_t subkeys[16] = {0}, subkeys_rev[16] = {0};
    
    printf("    ____     ______   _____\n");
    printf("   / __ \\   / ____/  / ___/\n");
    printf("  / / / /  / __/     \\__ \\ \n");
    printf(" / /_/ /  / /___    ___/ / \n");
    printf("/_____/  /_____/   /____/   \n");
    printf("\n");

    fprintf(stderr, "Message: %" PRIX64 "\n", M);
    fprintf(stderr, "Key: %" PRIX64 "\n", K);
    fprintf(stderr, "Mode: %s\n", encrypt ? "Encrypt" : "Decrypt");

    clock_t begin = clock();
    
    gen_subkeys(key, subkeys);

    if (!encrypt) {
        for (int i = 0; i < 16; i++)
            subkeys_rev[i] = subkeys[15 - i];
    } 

    uint64_t output = des(M, K, encrypt ? subkeys : subkeys_rev);

    clock_t end = clock();

    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

    fprintf(stderr, "%s: %" PRIX64 "\n", encrypt ? "Ciphertext" : "Plaintext", output);
    fprintf(stderr, "Execution time: %f seconds\n", time_spent);
    return (EXIT_SUCCESS);
}
