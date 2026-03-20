#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#pragma GCC diagnostic pop

#define AES_BLOCK_SIZE 16

/* Вывод данных в шестнадцатеричном формате */
void print_hex(const unsigned char *data, size_t len, const char *label) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
        else if ((i + 1) % 4 == 0)
            printf(" ");
    }
    if (len % 16 != 0)
        printf("\n");
    printf("\n");
}

/* Чтение всего файла в буфер (память) */
unsigned char *read_file(const char *filename, size_t *len) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size < 0) {
        perror("ftell");
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *) malloc(size);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, size, f) != (size_t)size) {
        perror("fread");
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = size;
    return buf;
}

/* Запись данных в файл */
int write_file(const char *filename, const unsigned char *data, size_t len) {
    if (!filename) return 0;
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("fopen write");
        return 0;
    }
    if (fwrite(data, 1, len, f) != len) {
        perror("fwrite");
        fclose(f);
        return 0;
    }
    fclose(f);
    return 1;
}

/* Расшифровка AES-CBC с известным IV (IV находится в начале шифротекста) */
unsigned char *decrypt(const EVP_CIPHER *cipher, const unsigned char *key,
                       const unsigned char *ciphertext, size_t ciphertext_len,
                       const unsigned char *iv, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return NULL;
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    unsigned char *plaintext = (unsigned char *) malloc(ciphertext_len + AES_BLOCK_SIZE);
    if (!plaintext) {
        fprintf(stderr, "malloc plaintext failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int) ciphertext_len)) {
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    *plaintext_len = len;

    int tmplen;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &tmplen)) {
        fprintf(stderr, "EVP_DecryptFinal_ex failed\n");
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    *plaintext_len += tmplen;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
                       }

                       /* Шифрование AES-CBC с новым случайным IV */
                       unsigned char *encrypt(const EVP_CIPHER *cipher, const unsigned char *key,
const unsigned char *plaintext, size_t plaintext_len,
unsigned char *iv, size_t *ciphertext_len) {
if (1 != RAND_bytes(iv, AES_BLOCK_SIZE)) {
    fprintf(stderr, "RAND_bytes failed\n");
    return NULL;
}

EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx) {
    fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
    return NULL;
}

if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
    fprintf(stderr, "EVP_EncryptInit_ex failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

unsigned char *ciphertext = (unsigned char *) malloc(plaintext_len + AES_BLOCK_SIZE);
if (!ciphertext) {
    fprintf(stderr, "malloc ciphertext failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

int len;
if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int) plaintext_len)) {
    fprintf(stderr, "EVP_EncryptUpdate failed\n");
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}
*ciphertext_len = len;

int tmplen;
if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &tmplen)) {
    fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}
*ciphertext_len += tmplen;

EVP_CIPHER_CTX_free(ctx);
return ciphertext;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <keyfile> <encrypted_file> [plain_output] [cipher_output]\n", argv[0]);
        fprintf(stderr, "  encrypted_file must start with 16-byte IV followed by ciphertext\n");
        return 1;
    }

    const char *keyfile = argv[1];
    const char *encfile = argv[2];
    const char *plain_out = (argc > 3) ? argv[3] : NULL;
    const char *cipher_out = (argc > 4) ? argv[4] : NULL;

    // 1. Чтение ключа
    size_t key_len;
    unsigned char *key = read_file(keyfile, &key_len);
    if (!key) {
        fprintf(stderr, "Failed to read key file\n");
        return 1;
    }

    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_cbc();
    else if (key_len == 24) cipher = EVP_aes_192_cbc();
    else if (key_len == 32) cipher = EVP_aes_256_cbc();
    else {
        fprintf(stderr, "Key length must be 16, 24, or 32 bytes (got %zu)\n", key_len);
        free(key);
        return 1;
    }

    // 2. Чтение зашифрованного файла (IV + шифротекст)
    size_t enc_len;
    unsigned char *enc_data = read_file(encfile, &enc_len);
    if (!enc_data) {
        free(key);
        return 1;
    }
    if (enc_len < AES_BLOCK_SIZE) {
        fprintf(stderr, "Encrypted file too small, must contain at least 16-byte IV\n");
        free(key);
        free(enc_data);
        return 1;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, enc_data, AES_BLOCK_SIZE);
    unsigned char *ciphertext = enc_data + AES_BLOCK_SIZE;
    size_t ciphertext_len = enc_len - 16; // AES_BLOCK_SIZE;

    // 3. Расшифровка
    size_t plaintext_len;
    unsigned char *plaintext = decrypt(cipher, key, ciphertext, ciphertext_len, iv, &plaintext_len);
    if (!plaintext) {
        fprintf(stderr, "Decryption failed\n");
        free(key);
        free(enc_data);
        return 1;
    }

    // Вывод расшифрованного содержимого
    print_hex(plaintext, plaintext_len, "Decrypted plaintext");

    // Опциональная запись расшифрованного в файл
    if (plain_out && !write_file(plain_out, plaintext, plaintext_len)) {
        fprintf(stderr, "Failed to write plaintext to file\n");
    }

    // 4. Повторное шифрование с новым IV
    unsigned char new_iv[AES_BLOCK_SIZE];
    size_t new_ciphertext_len;
    unsigned char *new_ciphertext = encrypt(cipher, key, plaintext, plaintext_len, new_iv, &new_ciphertext_len);
    if (!new_ciphertext) {
        fprintf(stderr, "Encryption failed\n");
        free(key);
        free(enc_data);
        free(plaintext);
        return 1;
    }

    // Формируем полный файл: новый IV + шифротекст
    size_t new_total_len = AES_BLOCK_SIZE + new_ciphertext_len;
    unsigned char *new_total = (unsigned char *) malloc(new_total_len);
    if (!new_total) {
        fprintf(stderr, "malloc new_total failed\n");
        free(key);
        free(enc_data);
        free(plaintext);
        free(new_ciphertext);
        return 1;
    }
    memcpy(new_total, new_iv, AES_BLOCK_SIZE);
    memcpy(new_total + AES_BLOCK_SIZE, new_ciphertext, new_ciphertext_len);

    // Вывод нового зашифрованного содержимого
    print_hex(new_total, new_total_len, "Re-encrypted data (IV + ciphertext)");

    // Опциональная запись нового шифротекста в файл
    if (cipher_out && !write_file(cipher_out, new_total, new_total_len)) {
        fprintf(stderr, "Failed to write new ciphertext to file\n");
    }

    // Очистка
    free(key);
    free(enc_data);
    free(plaintext);
    free(new_ciphertext);
    free(new_total);

    return 0;
}
