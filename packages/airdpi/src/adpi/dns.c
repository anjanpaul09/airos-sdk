#include "air_coplane.h"
#include "dns.h"

#include <linux/types.h>
#include <linux/limits.h>

// Define UINT32_MAX manually if not already defined
#ifndef UINT32_MAX
#define UINT32_MAX (~0U)
#endif

extern struct airpro_coplane *coplane;
#define MAX_DNS_LENGTH         256

void update_vif_top_domains(const char *domain_name) 
{
    int i, min_index = -1;
    uint32_t min_count = UINT32_MAX;

    spin_lock(&coplane->domain_lock);

    // Check if the domain already exists in the top list
    for (i = 0; i < MAX_DOMAINS; i++) {
        if (strcmp(coplane->top_domains[i].domain, domain_name) == 0) {
            coplane->top_domains[i].count++;
            spin_unlock(&coplane->domain_lock);
            return;
        }
        if (coplane->top_domains[i].count < min_count) {
            min_count = coplane->top_domains[i].count;
            min_index = i;
        }
    }

    // If the domain is not in the list and there's space, add it
    if (min_index != -1 && coplane->top_domains[min_index].count == 0) {
        strncpy(coplane->top_domains[min_index].domain, domain_name, MAX_DOMAIN_NAME_LEN - 1);
        coplane->top_domains[min_index].domain[MAX_DOMAIN_NAME_LEN - 1] = '\0';
        coplane->top_domains[min_index].count = 1;
        spin_unlock(&coplane->domain_lock);
        return;
    }

    // Replace the domain with the least count if the new domain is more frequent
    if (min_index != -1 && 1 > min_count) {
        strncpy(coplane->top_domains[min_index].domain, domain_name, MAX_DOMAIN_NAME_LEN - 1);
        coplane->top_domains[min_index].domain[MAX_DOMAIN_NAME_LEN - 1] = '\0';
        coplane->top_domains[min_index].count = 1;
    }

    spin_unlock(&coplane->domain_lock);
}


static int dns_get_name(unsigned char *buf, uint8_t *pos, uint8_t *q_name, int max_len, uint32_t *chars_parsed)
{
    uint8_t *q = pos;
    uint8_t *end = buf + max_len;
    uint8_t nlen = (uint8_t )*q;
    uint16_t offset;
    uint8_t pointer_found = 0;
    uint8_t *q_name_max = q_name + MAX_DNS_LENGTH;

    max_len -= sizeof(struct dns_hdr);
    while (nlen != 0) {
       q++;
       switch (nlen & 0xc0) {
           case 0x00:
               if (q + nlen > end) {
                   return 0;
               }
               if (!pointer_found) (*chars_parsed)++;
               while (nlen && (q_name < q_name_max)) {
                  *q_name++ = *q++;
                  if (!pointer_found) (*chars_parsed)++;
                  nlen--;
               }
               if (nlen) {
                  return 0;
               }

               nlen = *q;
               if (nlen != 0) {
                   if (unlikely(q_name == q_name_max)) {
                       return 0;
                   }
                   *q_name++ = 0x2e; // '.'
               }
               break;
          case 0xc0:
               offset =  ((nlen & 0x3f) << 8) | *(q); // skip the first two bits and read rest all 14 bits for getting the offset value
               q = buf + offset;
               nlen = (uint8_t )*q;
               if (q + nlen > end) { printk("corrupt pkt, nlen=%d\n", nlen); return 0;}
               if (!pointer_found) {
                   (*chars_parsed) += 2;
                   pointer_found = 1;
               }
               break;
        }
    }
    *q_name = '\0';
    if (!pointer_found) {
        (*chars_parsed)++; // increment for the last byte which was the end of label
    }

    return 1;
}

static int parse_dns_response(struct sk_buff *skb, unsigned int ofs)
{
    uint8_t *buf = (uint8_t *)(skb->data + ofs);
    const struct dns_hdr *dns = (const struct dns_hdr *)buf;
    int buf_len = skb->len - ofs;
    uint32_t chars_parsed = 0;
    uint8_t q_name[MAX_DNS_LENGTH] = {0};
    uint8_t *pos = buf;
    //uint8_t count = 0;

    if (dns->q_count == 0) {
       return 0;
    }
    pos += sizeof(struct dns_hdr);

    if (!dns_get_name(buf, pos, q_name, buf_len, &chars_parsed)) {
        printk("DNS response corrupt: no name found, skip the parsing of Answer section:%d\n", __LINE__);
        return 0;
    }

    update_vif_top_domains(q_name);
    //printk("Anjan: q_name=%s\n", q_name);

    return 1;
}

int snoop_dns_response(struct sk_buff *skb, unsigned int ofs)
{
    const struct dns_hdr *dns = (const struct dns_hdr *) (skb->data + ofs);
    int ret = 0;

    if (dns->qr == DNS_MSG_QUERY_RSP && dns->rcode == DNS_RCODE_NO_ERROR && dns->ans_count) {
        // if no error and we have any answers in this response then only we will parse else skip it
        parse_dns_response(skb, ofs);
    }

    return ret;
}

