#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>



#define KEY "/usb_keystorage/key.bin"
#define SNAPPER_BLOCK "/snapper/snapper_block.raw"
#define ENC_SNAPPER_BLOCK "/snapper/snapper_block.raw.enc"
#define DEC_PATH "/tmp/snapper_block.raw"

#define AES_KEY_LEN 32          /* 256 бит */
#define AES_IV_LEN  12          /* 96 бит, для GCM по умолчанию */
#define AES_TAG_LEN 16          /* 128 бит аутентификационный тэг */
#define BUF_SIZE   65536        /* 64KB */

void handleErrors(const char *msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/* Читает ровно len байт из fd в buf или ошибается */
ssize_t read_full(int fd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, (char*)buf + total, len - total);
        if (r < 0) handleErrors("read");
        if (r == 0) break;
        total += r;
    }
    return total;
}

int main() {
    // if (argc < 4) {
    //     fprintf(stderr, "Usage: %s <encrypted_file> <temp_decrypted_file> <key_file>\n", argv[0]);
    //     return EXIT_FAILURE;
    // }
    const char *enc_path = SNAPPER_BLOCK; // argv[1];
    const char *dec_path = DEC_PATH; // argv[2];
    const char *key_path = KEY; // argv[3];
    
    off_t ciphertext_len;
    int ret;
    unsigned char tag[AES_TAG_LEN];
    unsigned char iv[AES_IV_LEN];
    unsigned char inbuf[BUF_SIZE], outbuf[BUF_SIZE];
    int outlen, tmplen;
    int chunk;
    off_t remaining;
    EVP_CIPHER_CTX *ctx;

    /* Чтение ключа (32 байта) */
    unsigned char key[AES_KEY_LEN];
    int kfd = open(key_path, O_RDONLY);

    if (kfd < 0) {
        handleErrors("open key file");
    }

    if (read_full(kfd, key, AES_KEY_LEN) != AES_KEY_LEN) {
        fprintf(stderr, "Key file too short\n");
        close(kfd);
        return EXIT_FAILURE;
    }

    close(kfd);

    /* Открыть зашифрованный вход */
    int ifd = open(enc_path, O_RDONLY);
    if (ifd < 0) handleErrors("open encrypted file");

    /* Создать временный файл (предотвратить перезапись) */
    int ofd = open(dec_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (ofd < 0) handleErrors("open temp decrypted file");

    /* Получить размер входного файла */
    struct stat st;
    if (fstat(ifd, &st) < 0) handleErrors("fstat");
    off_t file_size = st.st_size;
    if (file_size < AES_IV_LEN + AES_TAG_LEN) {
        fprintf(stderr, "Input file too small\n");
        goto err;
    }
    ciphertext_len = file_size - AES_IV_LEN - AES_TAG_LEN;

    /* Считать IV из начала файла */
    if (read_full(ifd, iv, AES_IV_LEN) != AES_IV_LEN) handleErrors("read IV");

    /* Инициализация контекста AES-256-GCM */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("EVP_CIPHER_CTX_new");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        handleErrors("EVP_DecryptInit_ex");
    /* Установить длину IV (необязательно, 12 байт – дефолт) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AES_IV_LEN, NULL) != 1)
        handleErrors("EVP_CIPHER_CTX_ctrl IVLEN");
    /* Передать ключ и IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        handleErrors("EVP_DecryptInit_ex key/iv");

    /* Буферы для чтения шифротекста и записи открытого */
    
    remaining = ciphertext_len;

    while (remaining > 0) {
        chunk = (remaining > BUF_SIZE) ? BUF_SIZE : remaining;
        
        if (read_full(ifd, inbuf, chunk) != chunk) {
            handleErrors("read ciphertext");
        }
        /* Расшифровать блок */
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, chunk) != 1) {
            handleErrors("EVP_DecryptUpdate");
        }
        /* Записать открытый текст */
        if (write(ofd, outbuf, outlen) != outlen) {
            handleErrors("write decrypted");
        }

        remaining -= chunk;
    }

    /* Считать тэг аутентификации из конца входного файла */
    if (read_full(ifd, tag, AES_TAG_LEN) != AES_TAG_LEN) {
        handleErrors("read tag");
    }

    /* Установить ожидаемый тэг и проверить целостность */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AES_TAG_LEN, tag) != 1) {
        handleErrors("EVP_CIPHER_CTX_ctrl TAG");
    }

    ret = EVP_DecryptFinal_ex(ctx, outbuf, &tmplen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        /* Успех аутентификации – переименовать temp->orig (атомарно) */
        if (rename(dec_path, enc_path) != 0) handleErrors("rename");
        printf("Decryption successful, replaced '%s' with decrypted data.\n", enc_path);
    } else {
        /* Сбой верификации – удалить temp и выйти с ошибкой */
        fprintf(stderr, "Authentication failed: tag mismatch.\n");
        goto err;
    }

    /* Очистить ключ и буферы */
    OPENSSL_cleanse(key, AES_KEY_LEN);
    OPENSSL_cleanse(iv, AES_IV_LEN);
    OPENSSL_cleanse(tag, AES_TAG_LEN);
    OPENSSL_cleanse(inbuf, BUF_SIZE);
    OPENSSL_cleanse(outbuf, BUF_SIZE);
    close(ifd);
    close(ofd);
    return EXIT_SUCCESS;

err:
    /* Ошибка – очистка и выход */
    unlink(dec_path);
    OPENSSL_cleanse(key, AES_KEY_LEN);
    /* (другие буферы также очищаем перед выходом) */
    close(ifd);
    close(ofd);
    return EXIT_FAILURE;
}

/* Отключённый блок: пример шифрования тем же ключом и форматом файлов */
#if 0
void encrypt_file(const char *inpath, const char *outpath, unsigned char *key) {
    /* Здесь можно реализовать обратную операцию: чтение открытого файла,
       генерация случайного IV, EVP_EncryptInit_ex с EVP_aes_256_gcm(),
       последовательная EVP_EncryptUpdate и получение тега через EVP_CTRL_GCM_GET_TAG,
       а затем запись [IV|CIPHERTEXT|TAG] в outpath. */
}
#endif

#pragma GCC diagnostic pop


















// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Wconversion"
// #include <stdio.h>
// #include <stdlib.h>
// #include <stddef.h>
// #pragma GCC diagnostic pop

// #define FILE_NAME "/usb_keystorage/test.txt"
// #define WFILE_NAME "/usb_keystorage/wtest.txt"

// #pragma GCC diagnostic ignored "-Wunused-parameter"
// int main(int argc, char** argv) {
//     char* buf = (char*) calloc(16, sizeof(char));
//     FILE* test_file = fopen(FILE_NAME, "r");

//     if (test_file == NULL) {
//         perror("Cannot opet the file!");
//         return 1;
//     }

//     if (fread(buf, 1, 16, test_file) == 0) {
//         perror("Reading error!");
//         return 1;
//     }

//     fclose(test_file);
//     printf("\n\n\n%s\n\n\n", buf);

//     FILE* wtest_file = fopen(WFILE_NAME, "w");

//     if (wtest_file == NULL) {
//         perror("Cannot opet the wfile!");
//         return 1;
//     }

//     if (fwrite(buf, 1, 16, wtest_file) == 0) {
//         perror("Writing error!");
//         return 1;
//     }

//     fclose(wtest_file);

//     free(buf);
//     return 0;
// }
