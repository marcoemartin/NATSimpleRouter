
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_utils.h"

typedef enum {
    nat_mapping_icmp,
    nat_mapping_tcp
    /* NOTE: NAT not required to handle UDP as per assignment instructions */
    /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
    /* add TCP connection state data members here */

    /* TODO: implement */

    struct sr_nat_connection* next;
};

struct sr_nat_mapping {
    sr_nat_mapping_type type;
    uint32_t ip_int; /* internal ip addr */
    uint32_t ip_ext; /* external ip addr */
    uint16_t aux_int; /* internal port or icmp id */
    uint16_t aux_ext; /* external port or icmp id */
    time_t last_updated; /* use to timeout mappings */
    struct sr_nat_connection* conns; /* list of connections. null for ICMP */
    struct sr_nat_mapping* next;
};

struct sr_nat {
    /* fields */
    struct sr_nat_mapping* mappings;

    /* NAT options */
    unsigned int icmp_query_timeout;
    unsigned int tcp_established_idle_timeout;
    unsigned int tcp_transitory_idle_timeout;

    /* threading */
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
    pthread_attr_t thread_attr;
    pthread_t thread;
};


int   sr_nat_init(struct sr_nat* nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat* nat);  /* Destroys the nat (free memory) */
void* sr_nat_timeout(void* nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping* sr_nat_lookup_external(struct sr_nat* nat,
        uint16_t aux_ext, sr_nat_mapping_type type);

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping* sr_nat_lookup_internal(struct sr_nat* nat,
        uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping* sr_nat_insert_mapping(
    struct sr_instance* sr,
    uint32_t ip_int,
    uint16_t aux_int,
    sr_nat_mapping_type type);

/*
    returns usable external port or icmp id that mapped for tuple:
    (ip_external_interface, type)
*/
uint16_t generate_unique_port(
    struct sr_nat* nat,
    uint32_t ip_external_interface, /* IP of external interface */
    uint16_t aux_int, /* internal port or icmp id */
    sr_nat_mapping_type type);

uint16_t gen_random_port(sr_nat_mapping_type type);

bool is_internal_interface(const char* interface);
bool is_external_interface(const char* interface);

uint16_t get_source_port(const uint8_t* packet, sr_nat_mapping_type map_type);
uint16_t get_dest_port(const uint8_t* packet, sr_nat_mapping_type map_type);
uint16_t get_port(const uint8_t* packet, sr_nat_mapping_type map_type, bool get_source);

void set_source_port(uint8_t* packet,  size_t original_packet_size, sr_nat_mapping_type map_type, uint32_t new_src_port);
void set_source_address(uint8_t* packet, uint32_t new_source_address);

void set_dest_address(uint8_t* packet, uint32_t new_dest_address);
void set_dest_port(uint8_t* packet, size_t original_packet_size, sr_nat_mapping_type map_type, uint32_t new_src_port);

void print_nat_map(struct sr_nat_mapping* nat_entry);

#endif
