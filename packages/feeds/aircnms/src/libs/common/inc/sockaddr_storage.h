#ifndef FSM_UTILS_H_INCLUDED
#define FSM_UTILS_H_INCLUDED

#include <netinet/in.h>
#include <stdbool.h>

/**
 * @brief Compares 2 structures containing a generic IP address
 *
 * @param a pointer to one IP address
 * @param b pointer the other IP address
 *
 * @return true if both addresses match
 */
bool sockaddr_storage_equals(struct sockaddr_storage *a, struct sockaddr_storage *b);

/**
 * @brief Compares 2 structures containing a generic IP address
 *
 * @param a pointer to one IP address
 * @param ip_bytes binary representation of the IP address to compare
 * @param len length of the ip_bytes array
 *
 * @return true if both addresses match
 */
bool sockaddr_storage_equals_addr(struct sockaddr_storage *a, uint8_t *ip_bytes, size_t len);

/**
 * @brief Allocates and populates a generic structure for an IP address
 *
 * Function will allocate and populate a generic structure based on
 * the textual IP address passed as argument
 *
 * @param af the address family (AF_INET or AF_INET6)
 * @param ip_str the textual representation of the IP address
 *
 * @return pointer to allocated structure, or NULL in case of an error
 * @remark Caller is responsible to release the memory allocated for
 *         the sockaddr_storage structure.
 */
struct sockaddr_storage *sockaddr_storage_create(int af, char *ip_str);

/**
 * @brief Populates a generic structure for an IP address
 *
 * Function will populate a generic structure based on
 * the AF family and IP address passed as argument
 *
 * @param af the address family (AF_INET or AF_INET6)
 * @param ip the binary representation of the IP address
 * @param dst the populated structure
 *
 * @remark Caller is responsible allocate the referenced destination.
 */
void sockaddr_storage_populate(int af, void *ip, struct sockaddr_storage *dst);

/**
 * @brief Copies a generic structure into another
 *
 *
 * @param to the generic structure to be copied
 * @param from the destination structure
 *
 * @remark Caller is responsible allocate the referenced destination.
 */
void sockaddr_storage_copy(struct sockaddr_storage *from, struct sockaddr_storage *to);

/**
 * @brief Creates string from a generic structure for an IP address
 *
 * @param af the address family (AF_INET or AF_INET6)
 * @param ip_str the textual representation of the IP address
 *
 * @remark Caller is responsible allocate the referenced destination string.
 */
void sockaddr_storage_str(struct sockaddr_storage *addr, char *output);

#endif /* FSM_UTILS_H_INCLUDED */
