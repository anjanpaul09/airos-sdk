#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// DHCP Fingerprint structure
typedef struct {
    char options[128];              // DHCP options requested (e.g., "1,33,3,6,12,15,28,51,58,59,119")
    char vendor_class[64];          // Vendor Class Identifier (Option 60)
    char os_name[32];
    char os_version[32];
    char device_type[32];
    char additional_info[64];
} DHCPFingerprint;

// DHCP Fingerprint database - Based on real-world data
DHCPFingerprint dhcp_db[] = {
    // Android Devices - Real fingerprints
    {"1,33,3,6,12,15,28,51,58,59,119", "dhcpcd-5.5.6", "Android", "10-14", "Smartphone", "Modern Android"},
    {"1,33,3,6,15,26,28,51,58,59", "", "Android", "Generic", "Smartphone", "Android OS"},
    {"1,121,33,3,6,28,51,58,59", "", "Android", "2.2-4.x", "Smartphone", "Older Android"},
    {"1,3,6,15,26,28,51,58,59,43", "", "Android", "Generic", "Smartphone", "Generic Android"},
    {"1,121,33,3,6,15,28,51,58,59", "", "Android", "HTC/Samsung", "Smartphone", "HTC/Samsung Android"},
    
    // iOS Devices - Real fingerprints
    {"1,121,3,6,15,119,252", "", "iOS", "14-17", "iPhone", "Modern iPhone"},
    {"1,121,3,6,15,114,119,252", "", "iOS", "12-17", "iPhone", "iPhone"},
    {"1,3,6,15,119,252", "", "iOS", "11-13", "iPhone/iPad", "Older iOS"},
    {"1,3,6,15,119,95,252,44,46,101", "", "iOS", "10-11", "iPhone/iPad", "iOS 10-11"},
    {"1,15,3,6", "", "iOS", "iPod", "iPod", "Apple iPod"},
    
    // macOS - Real fingerprints
    {"1,121,3,6,15,119,95,252,44,46", "", "macOS", "12+ Monterey", "Mac", "Apple Silicon/Intel"},
    {"1,3,6,15,119,95,252,44,46", "", "macOS", "10.15-11", "Mac", "Catalina/Big Sur"},
    {"1,3,6,15,119,252,95,44,46", "", "macOS", "10.14 Mojave", "Mac", "macOS Mojave"},
    
    // Windows Devices - Real fingerprints
    {"1,15,3,6,44,46,47,31,33,121,249,252,43", "MSFT 5.0", "Windows", "10/11", "PC", "Modern Windows"},
    {"1,3,6,15,31,33,43,44,46,47,119,121,249,252", "MSFT 5.0", "Windows", "10/11", "PC", "Windows 10/11"},
    {"1,15,3,6,44,46,47,31,33,121,249,43", "MSFT 5.0", "Windows", "8/8.1", "PC", "Windows 8"},
    {"1,15,3,6,44,46,47,31,33,249,43", "MSFT 5.0", "Windows", "7", "PC", "Windows 7"},
    {"1,3,6,15,44,46,47,31,33,43", "MSFT", "Windows", "XP/Vista", "PC", "Legacy Windows"},
    {"1,3,6,15,44,46,47", "MSFT 5.0", "Windows", "Server", "Server", "Windows Server"},
    
    // Linux Distributions - Real fingerprints
    {"1,28,2,3,15,6,119,12,44,47,26,121,42", "", "Linux", "Ubuntu 20.04+", "PC/Server", "Ubuntu Linux"},
    {"1,28,2,3,15,6,119,12", "", "Linux", "Debian 10+", "PC/Server", "Debian-based"},
    {"1,28,2,3,15,6,12,44,47,26", "", "Linux", "Debian-based", "PC/Server", "Debian/Ubuntu"},
    {"1,3,6,12,15,28,42,51,54,58,59", "", "Linux", "CentOS/RHEL", "Server", "Red Hat based"},
    {"1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,252,42", "", "Linux", "Fedora/RedHat", "PC", "Fedora/RHEL"},
    {"1,3,6,15,28,51,58,59", "dhcpcd", "Linux", "Generic", "PC/Server", "Generic Linux"},
    
    // Smart TVs and Streaming Devices - Real fingerprints
    {"1,3,6,12,15,28", "Samsung-TV", "Tizen", "TV OS", "Smart TV", "Samsung Smart TV"},
    {"1,3,6,15,12", "LG-TV", "webOS", "TV OS", "Smart TV", "LG Smart TV"},
    {"1,3,6,12,15,28,51,58,59", "Roku", "Roku OS", "Streaming", "Media Player", "Roku Device"},
    {"1,3,6,15,28,51,58,59,119", "", "Android TV", "Google TV", "Smart TV", "Android TV/Chromecast"},
    {"1,3,6,15,119", "Amazon Fire TV", "Fire OS", "Streaming", "Media Player", "Fire TV"},
    
    // Gaming Consoles - Real fingerprints
    {"1,3,6,15,12,28,40,41,42", "PlayStation", "Orbis OS", "PS4/PS5", "Console", "PlayStation"},
    {"1,3,6,15,28,33,40,41,42", "Xbox", "Xbox OS", "One/Series", "Console", "Xbox"},
    {"1,3,6,15,28,31,33,121", "Nintendo", "Horizon", "Switch", "Console", "Nintendo Switch"},
    
    // IoT and Smart Home - Real fingerprints
    {"1,3,6,15", "", "IoT", "Generic", "IoT Device", "Generic IoT/Embedded"},
    {"1,3,6,12", "", "IoT", "Smart Speaker", "Smart Home", "Echo/Smart Speaker"},
    {"1,3,6,15,119", "", "IoT", "Google Home", "Smart Home", "Google Assistant"},
    {"1,3,6", "", "IoT", "Simple Device", "IoT Device", "Basic IoT Device"},
    {"1,3,6,15,28", "", "IoT", "Smart Device", "IoT Device", "Smart Home Device"},
    
    // Network Devices - Real fingerprints
    {"1,3,6,12,15,28,42,51,54,58,59,119", "Cisco", "IOS", "Network", "Router/Switch", "Cisco Equipment"},
    {"1,3,6,15,44,46,47", "Ubiquiti", "EdgeOS", "Network", "Router/AP", "Ubiquiti"},
    {"1,3,6,12,15,17,28,42,234", "", "Network", "Access Point", "AP", "Wireless AP"},
    {"3,51,1,15,6,66,67,120,44,43,150,12,7,42", "", "Network", "Juniper", "Switch", "Juniper Switch"},
    
    // Printers - Real fingerprints
    {"1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,252,42", "", "Printer", "Samsung", "Printer", "Samsung Printer"},
    {"1,3,6,15,12,28,40,41,42", "HP", "Embedded", "Printer", "Printer", "HP Printer"},
    {"1,3,6,15,44,46", "Canon", "Embedded", "Printer", "Printer", "Canon Printer"},
    
    // Wearables - Real fingerprints
    {"1,3,6,15,28", "Apple Watch", "watchOS", "Smartwatch", "Wearable", "Apple Watch"},
    {"1,3,6,15", "Wear OS", "Android", "Smartwatch", "Wearable", "Android Watch"},
    
    // Other devices
    {"1,3,6,120", "", "Feature Phone", "Nokia/Sony", "Mobile", "Feature Phone"},
    {"54,51,6,1,3,26,15,120", "", "Feature Phone", "LG", "Mobile", "LG Feature Phone"}
};

int dhcp_db_size = sizeof(dhcp_db) / sizeof(DHCPFingerprint);

// Function to normalize fingerprint (remove spaces, ensure consistent format)
void normalize_fingerprint(char* dest, const char* src, size_t dest_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j < dest_size - 1; i++) {
        if (src[i] != ' ') {
            dest[j++] = src[i];
        }
    }
    dest[j] = '\0';
}

// Function to calculate fingerprint match score (thread-safe)
int calculate_match_score(const char* fp1, const char* fp2) {
    if (fp1 == NULL || fp2 == NULL) {
        return 0;
    }
    
    if (strcmp(fp1, fp2) == 0) {
        return 100;
    }
    
    // Count matching options without using strtok
    char s1[128], s2[128];
    strncpy(s1, fp1, sizeof(s1) - 1);
    strncpy(s2, fp2, sizeof(s2) - 1);
    s1[sizeof(s1) - 1] = '\0';
    s2[sizeof(s2) - 1] = '\0';
    
    int total1 = 0, total2 = 0, matches = 0;
    
    // Parse fp1 options
    char options1[50][10];  // Max 50 options, each up to 10 chars
    char *start1 = s1;
    char *comma1;
    
    while (*start1) {
        comma1 = strchr(start1, ',');
        if (comma1) {
            int len = comma1 - start1;
            if (len < 10) {
                strncpy(options1[total1], start1, len);
                options1[total1][len] = '\0';
                total1++;
            }
            start1 = comma1 + 1;
        } else {
            if (strlen(start1) < 10) {
                strcpy(options1[total1], start1);
                total1++;
            }
            break;
        }
    }
    
    // Parse fp2 options
    char options2[50][10];
    char *start2 = s2;
    char *comma2;
    
    while (*start2) {
        comma2 = strchr(start2, ',');
        if (comma2) {
            int len = comma2 - start2;
            if (len < 10) {
                strncpy(options2[total2], start2, len);
                options2[total2][len] = '\0';
                total2++;
            }
            start2 = comma2 + 1;
        } else {
            if (strlen(start2) < 10) {
                strcpy(options2[total2], start2);
                total2++;
            }
            break;
        }
    }
    
    // Count matches
    for (int i = 0; i < total1; i++) {
        for (int j = 0; j < total2; j++) {
            if (strcmp(options1[i], options2[j]) == 0) {
                matches++;
                break;
            }
        }
    }
    
    // Calculate score based on matches
    int max_total = (total1 > total2) ? total1 : total2;
    if (max_total > 0) {
        return (matches * 100) / max_total;
    }
    
    return 0;
}

// Function to get OS/Device info from DHCP fingerprint
const DHCPFingerprint* get_device_from_dhcp(const char* options, const char* vendor_class) {
    if (options == NULL) {
        return NULL;
    }
    
    int best_match = -1;
    int max_score = 0;
    
    char normalized_options[128];
    normalize_fingerprint(normalized_options, options, sizeof(normalized_options));
    
    for (int i = 0; i < dhcp_db_size; i++) {
        int score = 0;
        
        // Check DHCP options matching
        char normalized_db[128];
        normalize_fingerprint(normalized_db, dhcp_db[i].options, sizeof(normalized_db));
        
        int options_score = calculate_match_score(normalized_options, normalized_db);
        score = options_score;
        
        // Check vendor class if provided (strong indicator)
        if (vendor_class != NULL && strlen(vendor_class) > 0 && strlen(dhcp_db[i].vendor_class) > 0) {
            if (strstr(vendor_class, dhcp_db[i].vendor_class) != NULL || 
                strstr(dhcp_db[i].vendor_class, vendor_class) != NULL) {
                score += 30;  // Boost score for vendor match
            }
        }
        
        // Update best match
        if (score > max_score) {
            max_score = score;
            best_match = i;
        }
    }
    
    // Return best match if confidence is reasonable (>60%)
    if (max_score >= 60 && best_match >= 0) {
        return &dhcp_db[best_match];
    }
    
    return NULL;
}

// Simple function that returns OS info string from fingerprint
char* get_os_info(const char* options, const char* vendor_class) {
    static char os_info[256];
    
    if (options == NULL || strlen(options) == 0) {
        strcpy(os_info, "Unknown");
        return os_info;
    }
    
    const DHCPFingerprint* device = get_device_from_dhcp(options, vendor_class);
    
    if (device == NULL) {
        strcpy(os_info, "Unknown");
        return os_info;
    }
    
    // Format: "OS Version (Device Type)"
    snprintf(os_info, sizeof(os_info), "%s", 
             device->os_name);
    //snprintf(os_info, sizeof(os_info), "%s %s (%s)", 
      //       device->os_name, 
        //     device->os_version, 
          //   device->device_type);
    
    return os_info;
}

// Function to print device information
void print_device_info(const DHCPFingerprint* device, int confidence) {
    if (device == NULL) {
        printf("Device: Unknown\n");
        printf("Unable to determine device from DHCP fingerprint.\n");
        return;
    }
    
    printf("DHCP Fingerprint Analysis:\n");
    printf("==========================\n");
    printf("OS/Platform:      %s\n", device->os_name);
    printf("Version:          %s\n", device->os_version);
    printf("Device Type:      %s\n", device->device_type);
    printf("Additional Info:  %s\n", device->additional_info);
    printf("Confidence:       %d%%\n", confidence > 100 ? 100 : confidence);
    printf("\nFingerprint Details:\n");
    printf("DHCP Options:     %s\n", device->options);
    if (strlen(device->vendor_class) > 0) {
        printf("Vendor Class:     %s\n", device->vendor_class);
    }
}

// Function to explain DHCP options
void explain_dhcp_options(const char* options) {
    printf("\nDHCP Options Breakdown:\n");
    printf("=======================\n");
    
    char opts[128];
    strncpy(opts, options, sizeof(opts) - 1);
    opts[sizeof(opts) - 1] = '\0';
    
    char* token = strtok(opts, ",");
    while (token != NULL) {
        int opt = atoi(token);
        printf("Option %3d: ", opt);
        
        switch(opt) {
            case 1: printf("Subnet Mask\n"); break;
            case 2: printf("Time Offset\n"); break;
            case 3: printf("Router/Gateway\n"); break;
            case 6: printf("DNS Server\n"); break;
            case 12: printf("Hostname\n"); break;
            case 15: printf("Domain Name\n"); break;
            case 28: printf("Broadcast Address\n"); break;
            case 31: printf("Router Discovery\n"); break;
            case 33: printf("Static Route\n"); break;
            case 40: printf("NIS Domain\n"); break;
            case 41: printf("NIS Servers\n"); break;
            case 42: printf("NTP Servers\n"); break;
            case 43: printf("Vendor Specific Info\n"); break;
            case 44: printf("NetBIOS Name Server\n"); break;
            case 46: printf("NetBIOS Node Type\n"); break;
            case 47: printf("NetBIOS Scope\n"); break;
            case 51: printf("IP Address Lease Time\n"); break;
            case 54: printf("DHCP Server Identifier\n"); break;
            case 58: printf("Renewal Time (T1)\n"); break;
            case 59: printf("Rebinding Time (T2)\n"); break;
            case 66: printf("TFTP Server Name\n"); break;
            case 67: printf("Bootfile Name\n"); break;
            case 95: printf("LDAP Servers\n"); break;
            case 114: printf("URL\n"); break;
            case 119: printf("Domain Search List\n"); break;
            case 120: printf("SIP Servers\n"); break;
            case 121: printf("Classless Static Route\n"); break;
            case 249: printf("Microsoft Classless Static Route\n"); break;
            case 252: printf("Proxy Auto-Discovery\n"); break;
            default: printf("Other/Vendor Specific\n"); break;
        }
        
        token = strtok(NULL, ",");
    }
}

# if 0
// Example usage
int main() {
    printf("DHCP Fingerprinting System\n");
    printf("==========================\n\n");
    
    // Simple usage - just get OS info string
    printf("Simple OS Info Retrieval:\n");
    printf("-------------------------\n");
    printf("Your phone: %s\n", get_os_info("1,33,3,6,12,15,28,51,58,59,119", ""));
    printf("iPhone: %s\n", get_os_info("1,121,3,6,15,119,252", "MSFT 5.0"));
    printf("Windows 10: %s\n", get_os_info("1,15,3,6,44,46,47,31,33,121,249,252,43", "MSFT 5.0"));
    printf("Ubuntu: %s\n", get_os_info("1,28,2,3,15,6,119,12,44,47,26,121,42", ""));
    printf("Samsung TV: %s\n", get_os_info("1,3,6,12,15,28", "Samsung-TV"));
    
    printf("\n\n");
    
    // Detailed analysis example
    printf("Detailed Analysis Example:\n");
    printf("--------------------------\n");
    printf("Test 1 - Your Phone:\n");
    const DHCPFingerprint* device1 = get_device_from_dhcp("1,33,3,6,12,15,28,51,58,59,119", "");
    print_device_info(device1, 95);
    explain_dhcp_options("1,33,3,6,12,15,28,51,58,59,119");
    
    return 0;
}
#endif
