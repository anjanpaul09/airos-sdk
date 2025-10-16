#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <errno.h>
#include "dm.h"
#include "MT7621.h"

#define MAX_PATH_LEN 256

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
    return fwrite(ptr, size, nmemb, stream);
}

int download_file(const char *url, const char *output_file, const char *json_data)
{
    CURL *curl;
    FILE *file;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        file = fopen(output_file, "wb");
        if (!file) {
            fprintf(stderr, "Could not open file for writing: %s\n", output_file);
            return 1;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        fclose(file);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        return (res == CURLE_OK) ? 0 : 1;
    }

    return 1;
}


int run_command(const char *command, char *output, size_t size) 
{
    FILE *fp;
    fp = popen(command, "r");
    if (!fp) {
        fprintf(stderr, "Failed to run command: %s\n", command);
        return 1;
    }

    if (fgets(output, size, fp) != NULL) {
        output[strcspn(output, "\n")] = 0;
    }

    pclose(fp);
    return 0;
}


int target_cmd_device_upgrade() 
{
    const char *url = DM_FW_UPGRADE_URL;   
    const char *output_tar = FW_OUTPUT_TAR;  
    const char *extracted_folder = FW_EXTRACTED_FOLDER; // e.g., "/tmp/air-image"
    char cmd[256];
    char img_md5sum[128];
    char bin_md5sum[128];
    char bin_filename[128];
    char json_request[256];
    
    sprintf(json_request, "{\"device_firmware_id\": \"%s\"}", fw_id);

    // Download the .tar.gz file using curl    
    printf("Downloading file from: %s\n", url);
    if (download_file(url, output_tar, json_request) != 0) {
        fprintf(stderr, "File download failed\n");
        dm_send_event_to_cloud(UPGRADE, FAILED, NULL, fw_id);
        return 1;
    }

    dm_send_event_to_cloud(UPGRADE, DOWNLOADED, NULL, fw_id);    //sending status to cloud

    // Extract the .tar.gz file
    printf("Extracting tar.gz file to %s...\n", extracted_folder);
    char extract_command[256];
    snprintf(extract_command, sizeof(extract_command), 
         "mkdir -p %s && tar -xvzf %s -C %s 2> /tmp/tar_error.log",
         extracted_folder, output_tar, extracted_folder);

    if (system(extract_command) != 0) {
        fprintf(stderr, "Error extracting tar.gz file. Check /tmp/tar_error.log for details.\n");
        dm_send_event_to_cloud(UPGRADE, FAILED, NULL, fw_id);
        return 1;
    }

    // Locate the md5sum file using find. This will find a file named "md5sum" in
    // the extracted folder (even if it's in a subdirectory)
    char find_cmd[256];
    char img_md5sum_path[MAX_PATH_LEN];
    FILE *fp;

    snprintf(find_cmd, sizeof(find_cmd), "find %s -maxdepth 2 -name md5sum", extracted_folder);
    fp = popen(find_cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error executing find command: %s\n", strerror(errno));
        return 1;
    }
    if (fgets(img_md5sum_path, sizeof(img_md5sum_path), fp) == NULL) {
        fprintf(stderr, "Could not locate md5sum file.\n");
        pclose(fp);
        return 1;
    }
    pclose(fp);
    // Remove newline at end of path if present
    img_md5sum_path[strcspn(img_md5sum_path, "\n")] = '\0';

    // Open the md5sum file and read the expected md5 checksum
    FILE *md5sum_file = fopen(img_md5sum_path, "r");
    if (!md5sum_file) { 
        fprintf(stderr, "Could not open md5sum file at %s\n", img_md5sum_path);
        return 1;
    }
    if (fgets(img_md5sum, sizeof(img_md5sum), md5sum_file) == NULL) {
        fprintf(stderr, "Error reading md5sum file\n");
        fclose(md5sum_file);
        return 1;
    }
    fclose(md5sum_file);
    img_md5sum[strcspn(img_md5sum, "\n")] = '\0';
    printf("MD5 Sum: %s\n", img_md5sum);

    // Find the .bin file. This assumes there is one .bin file in the extracted folder.
    char find_bin_command[256];
    snprintf(find_bin_command, sizeof(find_bin_command), "find %s -name '*.bin'", extracted_folder);
    if (run_command(find_bin_command, bin_filename, sizeof(bin_filename)) != 0) {
        fprintf(stderr, "Error finding .bin file\n");
        return 1;
    }

    // Compute MD5 of the .bin file
    char md5_command[256];
    snprintf(md5_command, sizeof(md5_command), "md5sum %s | awk '{print $1}'", bin_filename);
    if (run_command(md5_command, bin_md5sum, sizeof(bin_md5sum)) != 0) {
        fprintf(stderr, "Error calculating MD5 of .bin file\n");
        return 1;
    }

    sprintf(cmd, "sysupgrade %s", bin_filename);
    // Compare the MD5s and print result
    if (strcmp(img_md5sum, bin_md5sum) == 0) {
        set_fw_upgrade_status_to_aircnms(UPGRADING);
        dm_send_event_to_cloud(UPGRADE, UPGRADING, NULL, fw_id);
        system(cmd);
        printf("MD5 Checksum OK\n");
    } else {
        dm_send_event_to_cloud(UPGRADE, FAILED, NULL, fw_id);
        printf("MD5 Checksum NOT OK\n");
    }

    return 0;
}

