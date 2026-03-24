#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#pragma GCC diagnostic pop

#define FILE_NAME "/mnt/test.txt"

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

    free(buf);
    return 0;
}
