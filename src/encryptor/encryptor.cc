#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#pragma GCC diagnostic pop

#define FILE_NAME "/usb_keystorage/test.txt"
#define WFILE_NAME "/usb_keystorage/wtest.txt"

#pragma GCC diagnostic ignored "-Wunused-parameter"
int main(int argc, char** argv) {
    char* buf = (char*) calloc(16, sizeof(char));
    FILE* test_file = fopen(FILE_NAME, "r");

    if (test_file == NULL) {
        perror("Cannot opet the file!");
        return 1;
    }

    if (fread(buf, 1, 16, test_file) == 0) {
        perror("Reading error!");
        return 1;
    }

    fclose(test_file);
    printf("\n\n\n%s\n\n\n", buf);

    FILE* wtest_file = fopen(WFILE_NAME, "w");

    if (wtest_file == NULL) {
        perror("Cannot opet the wfile!");
        return 1;
    }

    if (fwrite(buf, 1, 16, wtest_file) == 0) {
        perror("Writing error!");
        return 1;
    }

    fclose(wtest_file);

    free(buf);
    return 0;
}
