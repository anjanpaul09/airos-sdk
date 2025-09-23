#include <stdio.h>
#include <stdlib.h>

#define FILE_PATH "/tmp/setjson"
#define MAX_BUFFER_SIZE 8192  // Adjust buffer size if needed

// Function prototype for cm_process_set_msg()
void cm_process_set_msg(const char *buffer);

// Function to read the file and pass it to cm_process_set_msg()
void read_setjson_and_process() {
    FILE *file = fopen(FILE_PATH, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    // Allocate buffer dynamically
    char *buffer = (char *)malloc(MAX_BUFFER_SIZE);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return;
    }

    // Read file contents into buffer
    size_t bytesRead = fread(buffer, 1, MAX_BUFFER_SIZE - 1, file);
    fclose(file);

    if (bytesRead == 0) {
        fprintf(stderr, "Error: File is empty or read failed\n");
        free(buffer);
        return;
    }

    buffer[bytesRead] = '\0'; // Null-terminate the buffer

    // Call the processing function with the buffer
    cm_process_set_msg(buffer);

    // Free allocated memory
    free(buffer);
}

