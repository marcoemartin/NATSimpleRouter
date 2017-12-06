#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* arp_request) {

    /*
        2.3.2.1  ARP Cache Validation
        see: https://tools.ietf.org/html/rfc1122
    	2 Private
    */

    time_t now = time(NULL);

    /*  ARP requests are sent every second until we send 5 ARP requests,
      then we send ICMP host unreachable back to all packets waiting on this
      ARP request.
    */

    if(difftime(now, arp_request->sent) < 1.0) {
        return;
    }

    if(arp_request->times_sent >= 5) {

        /*
            Send ICMP host unreachable (code = 1) to all buffered packets
            waiting to be sent to arp_request->ip
        */

        /* Construct Internet Control Message Protocol (ICMP) message (type = 3) */

        size_t packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t* packet = (uint8_t*) malloc(packet_size);

        struct sr_packet* current_packet = arp_request->packets;

        while(current_packet != NULL) {

            uint8_t* original_packet = current_packet->buf;
            assert(original_packet);

            /* Fill in details for eth header */

            sr_ethernet_hdr_t* orig_eth_header = unwrap_eth_header(original_packet);
            sr_ethernet_hdr_t* eth_header = unwrap_eth_header(packet);

            /* TODO: code review; is this right??? */
            /* swap dest_address and source_address */

            uint8_t dest_eth_address[ETHER_ADDR_LEN];
            set_eth_address_with(dest_eth_address, orig_eth_header->ether_shost);

            uint8_t source_eth_address[ETHER_ADDR_LEN];
            set_eth_address_with(source_eth_address, orig_eth_header->ether_dhost);

            set_eth_header(
                eth_header,
                dest_eth_address,
                source_eth_address,
                ethertype_ip);

            /* Fill in details for IP header */

            sr_ip_hdr_t* orig_ip_header = unwrap_ip_header(original_packet);
            sr_ip_hdr_t* ip_header = unwrap_ip_header(packet);

            /* TODO: code review; right??? */
            struct sr_if* source_interface = sr_get_interface_by_eth_addr(sr, source_eth_address);
            assert(source_interface);
            uint32_t source_ip_address = source_interface->ip;

            uint32_t dest_ip_address = orig_ip_header->ip_src;

            set_ip_header(
                ip_header,
                sizeof(sr_icmp_t3_hdr_t),
                ip_protocol_icmp,
                source_ip_address,
                dest_ip_address);

            /* Fill in details for ICMP */

            sr_icmp_t3_hdr_t* icmp_header = unwrap_icmp_t3_header(packet);

            set_icmp_t3_header(
                icmp_header,
                1/*icmp_code,  Host unreachable error. */,
                orig_ip_header
            );

            /* send packet */

            sr_send_packet(sr, packet, packet_size, source_interface->name);

            current_packet = current_packet->next;
        }

        /* clean up */

        free(packet);

        struct sr_arpcache* cache_table = &(sr->cache);
        sr_arpreq_destroy(cache_table, arp_request);

        return;
    }

    /* Construct ARP request */

    size_t packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* packet = (uint8_t*) malloc(packet_size);

    /* Fill in details for eth header */

    sr_ethernet_hdr_t* eth_header = unwrap_eth_header(packet);

    /* Broadcast ARP request query over the network (i.e. 255.255.255.255) */
    unsigned char broadcast_address[ETHER_ADDR_LEN];
    fill_octets_with(broadcast_address, ETHER_ADDR_LEN, 255);

    const unsigned char* mac_source = NULL; /* MAC source will be changed; see below */
    set_eth_header(eth_header, broadcast_address, mac_source, ethertype_arp);

    /* Fill in details for ARP header */

    sr_arp_hdr_t* arp_header = unwrap_arp_header(packet);

    set_arp_header(
        arp_header,
        arp_op_request,
        NULL /* sender_hardware_address; this is filled below */,
        NULL /* sender_ip_address; this is filled below */,
        NULL /* target_hardware_address; unused for ARP requests */,
        &(arp_request->ip) /* target_ip_address */
    );

    /* send packet to all interfaces */

    /* resolve IP address */

    struct sr_if* source_interface = sr_get_interface(sr, arp_request->packets->iface);

    set_eth_address_with(eth_header->ether_shost, source_interface->addr);

    /* TODO: code review; right sender ip???? */
    arp_header->ar_sip = source_interface->ip; /* set sender ip */
    set_eth_address_with(arp_header->ar_sha, source_interface->addr);

    /* TODO: debug remove */
    printf("handle_arpreq/Sending ARP request packet to %s\n", source_interface->name);

    sr_send_packet(sr, packet, packet_size, source_interface->name);

    free(packet);

    /* Update metadata for this ARP request */

    arp_request->sent = now;
    arp_request->times_sent += 1;
}

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance* sr) {

    /*
        2.3.2.1  ARP Cache Validation
        see: https://tools.ietf.org/html/rfc1122
     */

    assert(sr);

    struct sr_arpcache* cache_table = &(sr->cache);
    struct sr_arpreq* current = cache_table->requests;

    while(current != NULL) {
        handle_arpreq(sr, current);
        current = current->next;
    }

}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry* sr_arpcache_lookup(struct sr_arpcache* cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry* entry = NULL, *copy = NULL;

    int i;

    for(i = 0; i < SR_ARPCACHE_SZ; i++) {
        if((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if(entry) {
        copy = (struct sr_arpentry*) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq* sr_arpcache_queuereq(struct sr_arpcache* cache,
                                       uint32_t ip,
                                       uint8_t* packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char* iface) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq* req;

    for(req = cache->requests; req != NULL; req = req->next) {
        if(req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if(!req) {
        req = (struct sr_arpreq*) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if(packet && packet_len && iface) {
        struct sr_packet* new_pkt = (struct sr_packet*)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t*)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char*)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq* sr_arpcache_insert(struct sr_arpcache* cache,
                                     unsigned char* mac,
                                     uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq* req, *prev = NULL, *next = NULL;

    for(req = cache->requests; req != NULL; req = req->next) {
        if(req->ip == ip) {
            if(prev) {
                next = req->next;
                prev->next = next;

            } else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }

        prev = req;
    }

    int i;

    for(i = 0; i < SR_ARPCACHE_SZ; i++) {
        if(!(cache->entries[i].valid)) {
            break;
        }
    }

    if(i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache* cache, struct sr_arpreq* entry) {
    pthread_mutex_lock(&(cache->lock));

    if(entry) {
        struct sr_arpreq* req, *prev = NULL, *next = NULL;

        for(req = cache->requests; req != NULL; req = req->next) {
            if(req == entry) {
                if(prev) {
                    next = req->next;
                    prev->next = next;

                } else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }

            prev = req;
        }

        struct sr_packet* pkt, *nxt;

        for(pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;

            if(pkt->buf) {
                free(pkt->buf);
            }

            if(pkt->iface) {
                free(pkt->iface);
            }

            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache* cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;

    for(i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry* cur = &(cache->entries[i]);
        unsigned char* mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache* cache) {
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache* cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void* sr_arpcache_timeout(void* sr_ptr) {
    struct sr_instance* sr = sr_ptr;
    struct sr_arpcache* cache = &(sr->cache);

    while(1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;

        for(i = 0; i < SR_ARPCACHE_SZ; i++) {
            if((cache->entries[i].valid) && (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}

