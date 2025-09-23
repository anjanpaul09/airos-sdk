#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "qm.h"
#include "os_time.h"
#include "log.h"
#include <sys/stat.h>
//Anjan
//#include "dppline.h"

#define LOG_FILE_SIZE 10000

long get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) != 0) {
        perror("Failed to get file size");
        return -1;
    }
    return st.st_size;
}

int qm_check_debug_status()
{
#define UCI_BUF_LEN 256
    char buf[UCI_BUF_LEN];
    size_t len;
    int status = 0;

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].debug", buf, (size_t)UCI_BUF_LEN);

    len = strlen(buf);
    if (len == 0) {
        LOGI("%s: No uci found", __func__);
        return 0; 
    }

    status = atoi(buf);

    return status;
}

void qm_log_msg(const char *filename, const char *msg, const char *topic) 
{
    if (msg == NULL || strlen(msg) == 0) {
        fprintf(stderr, "Message is empty\n");
        return;
    }

    // Open the file in append mode
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        // File does not exist, create it and check size
        file = fopen(filename, "w");
        if (file == NULL) {
            perror("Failed to create file");
            return;
        }
    }

    // Get the current file size
    long file_size = get_file_size(filename);
    if (file_size < 0) {
        return; // Error already printed by get_file_size()
    }

    size_t additional_size = strlen(msg) + strlen(topic) + 100; // Rough estimation
    if (file_size + additional_size > LOG_FILE_SIZE) {
        // Open the file again for truncation
        file = fopen(filename, "w");
        if (file == NULL) {
            perror("Failed to open file for truncation");
            return;
        }

        // Close the file after truncation
        if (fclose(file) != 0) {
            perror("Failed to close file after truncation");
            return;
        }

        // Reopen the file in append mode
        file = fopen(filename, "a");
        if (file == NULL) {
            perror("Failed to reopen file for appending after truncation");
            return;
        }
    }

    // Get the current time
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    if (t == NULL) {
        perror("Failed to get local time");
        fclose(file);
        return;
    }

    // Format the timestamp
    char timestamp[100];
    if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t) == 0) {
        perror("Failed to format timestamp");
        fclose(file);
        return;
    }
    
    if (fprintf(file, "-------------[%s]------------- \n", timestamp) < 0) {
        perror("Failed to write to file");
        fclose(file);
        return;
    }

    // Write the text to the file
    if (fprintf(file, "TOPIC:- %s \n MSG:- %s\n", topic, msg) < 0) {
        perror("Failed to write to file");
        fclose(file);
        return;
    }

    // Close the file
    if (fclose(file) != 0) {
        perror("Failed to close file");
    }
}
