#ifndef _DNSPCAP_PROTOCOL_
#define _DNSPCAP_PROTOCOL_

#include <stdlib.h>
#include <string.h>

/*
 * Get a domain name from DNS packet.
 * With the support of name compression.
 *   - bytes: pointer to the beginning of the DNS packet
 *   - ref_index: offset value that indicates the beginning of the name
 *   - dnslen: total length of the DNS packet
 * Returns:
 *     domain name in readable form, NULL if failed.
 *     After execution, ref_index indicates the next byte after the name.
 */
char *getname (const char *bytes, unsigned short *ref_index, unsigned short dnslen) {

    unsigned short index = *ref_index;
    unsigned short start = index;
    unsigned short labellen, i;
    
    // Domain name, 256 should be enough
    char *name = (char *)malloc(300 * sizeof(char));
    char *nameptr = name;
    
    // Read the name label by label
    while (bytes[index] != 0 && (bytes[index] & 0xC0) == 0) {
    	labellen = bytes[index];
        if (index + labellen >= dnslen) {
            free(name);
            return NULL;
        }
        strncpy(nameptr, bytes + index + 1, labellen);
        for (i = 0; i < labellen; i++) {
        	if (nameptr[i] < 32 || nameptr[i] > 126 || nameptr[i] == '\'') {
        		nameptr[i] = '_';
        	}
        }
        nameptr += labellen;
        *nameptr = '.';
        nameptr++;
        index += labellen + 1;
    }
    
    if ((bytes[index] & 0xC0) != 0) {
        // The name ends with a pointer
        unsigned short pointer = (bytes[index] & 0x3F) << 8 | bytes[index + 1];
        if (pointer >= dnslen) {
            free(name);
            return NULL;
        }
        // Resolve the omitted parts and append to the name
        char *parts = getname(bytes, &pointer, dnslen);
        if (!parts) {
            free(name);
            return NULL;
        }
        strcpy(nameptr, parts);
        nameptr += strlen(parts);
        free(parts);
        index += 2;
    } else {
        index += 1;
        // Remove the trailing dot
        *(nameptr - 1) = 0;
    }

    *ref_index = index;
    return name;
    
}

/*
 * Skip the domain name.
 *   - bytes: pointer to the beginning of the DNS packet
 *   - ref_index: offset value that indicates the beginning of the name
 * After execution, ref_index indicates the next byte after the name.
 */
void skipname (const char *bytes, unsigned short *ref_index) {

    unsigned short index = *ref_index;
    
    // Skip the name label by label
    while (bytes[index] && !(bytes[index] & 0xC0)) {
        index += bytes[index] + 1;
    }
    
    if (bytes[index] & 0xC0) {
        // The name ends with a pointer
        index += 2;
    } else {
        index += 1;
    }
    
    *ref_index = index;
    
}

#endif //_DNSPCAP_PROTOCOL_

