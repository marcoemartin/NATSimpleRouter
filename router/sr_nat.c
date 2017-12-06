#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include "sr_nat.h"
#include "sr_router.h"

int sr_nat_init(struct sr_nat* nat) { /* Initializes the nat */

    assert(nat);

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

    /* Initialize timeout thread */

    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

    /* Initialize any variables here */

    nat->mappings = NULL; /* tail of list */

    nat->icmp_query_timeout = 60;
    nat->tcp_established_idle_timeout = 7440;
    nat->tcp_transitory_idle_timeout = 300;

    /* TODO: check struct sr_nat fields */

    return success;
}


/* If success, return 0. */
int sr_nat_destroy(struct sr_nat* nat) {  /* Destroys the nat (free memory) */

    if(nat == NULL) {
        return 0;
    }

    pthread_mutex_lock(&(nat->lock));

    /* free nat memory here */

    /* TODO: complete; doesn't seem to be used */

    /* kill timeout thread */
    pthread_kill(nat->thread, SIGKILL);

    return pthread_mutex_destroy(&(nat->lock)) &&
           pthread_mutexattr_destroy(&(nat->attr));

}

void* sr_nat_timeout(void* nat_ptr) {  /* Periodic Timout handling */
    struct sr_nat* nat = (struct sr_nat*)nat_ptr;
    assert(nat);

    while(1) {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));

        time_t current_time = time(NULL);

        /* handle periodic tasks here */

        struct sr_nat_mapping* prev = NULL;
        struct sr_nat_mapping* current = nat->mappings;

        while(current != NULL) {

            bool should_splice = false;

            switch(current->type) {

            case nat_mapping_icmp:

                assert(current->conns == NULL);

                /* ICMP timeout */
                if(difftime(current_time, current->last_updated) >= (nat->icmp_query_timeout)) {
                    should_splice = true;
                }

                break;

            case nat_mapping_tcp:

                /* TODO: TCP timeout */

                /* TODO: complete */
                if(difftime(current_time, current->last_updated) >= (nat->tcp_established_idle_timeout)) {
                }

                /* TODO: complete; merge to above */
                if(difftime(current_time, current->last_updated) >= (nat->tcp_transitory_idle_timeout)) {
                }

                /* TODO: free current->conns if timeout */

                break;

            default:
                printf("DEBUG: unexpected sr_nat_mapping_type\n");
                assert(0);
            }

            if(should_splice) {
                /* splice out entry */

                if(prev != NULL) {
                    prev->next = current->next;

                } else {
                    /* invariant: entry is head of list */
                    nat->mappings = current->next;
                }

                /* clean up */

                current->next = NULL;
                free(current);

                if(prev != NULL) {
                    current = prev->next;

                } else {
                    current = nat->mappings;
                }

            } else {
                /* invariant: current was not spliced out of the map */

                prev = current;
                current = current->next;
            }

        }

        pthread_mutex_unlock(&(nat->lock));
    }

    return NULL;
}

/* Get the mapping associated with given external port.
    Returns NULL if no entry is found.
   You (caller) must free the returned structure if it is not NULL. */
struct sr_nat_mapping* sr_nat_lookup_external(struct sr_nat* nat,
        uint16_t aux_ext, sr_nat_mapping_type type) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy_of_entry. */
    struct sr_nat_mapping* copy_of_entry = NULL;

    struct sr_nat_mapping* current = nat->mappings;

    while(current != NULL) {

        if(current->type == type &&
                current->aux_ext == aux_ext) {

            copy_of_entry = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
            assert(copy_of_entry);
            memcpy(copy_of_entry, current, sizeof(struct sr_nat_mapping));

            time_t curr_time;
            time(&curr_time);
            current->last_updated = curr_time;

            break;
        }

        current = current->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy_of_entry;
}

/* Get the mapping associated with given internal (ip, port) pair.
   Returns NULL if no entry is found.
   You (caller) must free the returned structure if it is not NULL. */
struct sr_nat_mapping* sr_nat_lookup_internal(struct sr_nat* nat,
        uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy_of_entry. */
    struct sr_nat_mapping* copy_of_entry = NULL;

    struct sr_nat_mapping* current = nat->mappings;

    while(current != NULL) {

        if(current->type == type &&
                current->ip_int == ip_int &&
                current->aux_int == aux_int) {

            copy_of_entry = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
            assert(copy_of_entry);
            memcpy(copy_of_entry, current, sizeof(struct sr_nat_mapping));

            time_t curr_time;
            time(&curr_time);
            current->last_updated = curr_time;

            break;
        }

        current = current->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy_of_entry;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.

   Caller must free the returned entry.
 */
struct sr_nat_mapping* sr_nat_insert_mapping(struct sr_instance* sr,
        uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

    assert(sr);

    struct sr_nat* nat = &(sr->nat);

    pthread_mutex_lock(&(nat->lock));

    /* create mapping entry */

    struct sr_nat_mapping* new_entry = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
    assert(new_entry);

    /* populate entry */

    new_entry->type = type;
    new_entry->ip_int = ip_int; /* internal ip addr */

    /* fetch IP of external interface */
    /* ref: https://piazza.com/class/it0h3m8ljm37mb?cid=387 */
    struct sr_if* external_interface = sr_get_interface(sr, "eth2");
    assert(external_interface); /* assert interface exists */

    new_entry->ip_ext = external_interface->ip; /* external ip addr */

    new_entry->aux_int = aux_int; /* internal port or icmp id */
    new_entry->aux_ext = generate_unique_port(nat, external_interface->ip, aux_int, type); /* external port or icmp id */

    time_t curr_time;
    time(&curr_time);
    new_entry->last_updated = curr_time; /* use to timeout mappings */

    /* list of connections. null for ICMP */
    switch(type) {

    case nat_mapping_icmp:
        new_entry->conns = NULL;
        break;

    case nat_mapping_tcp:
        /* TODO: change this; what is this supposed to be? */
        new_entry->conns = NULL;
        break;

    default:
        printf("DEBUG: unexpected sr_nat_mapping_type\n");
        assert(0);
    }

    /* insert entry into the NAT map; new entry becomes the head */
    new_entry->next = nat->mappings;
    nat->mappings = new_entry;

    /* create copy of entry */

    struct sr_nat_mapping* copy_of_entry = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
    assert(copy_of_entry);
    memcpy(copy_of_entry, new_entry, sizeof(struct sr_nat_mapping));

    pthread_mutex_unlock(&(nat->lock));

    /* return copy of it */
    return copy_of_entry;
}

/*
    returns usable external port or icmp id that mapped for tuple:
    (ip_external_interface, type)
*/
uint16_t generate_unique_port(
    struct sr_nat* nat,
    uint32_t ip_external_interface, /* IP of external interface */
    uint16_t aux_int, /* internal port or icmp id */
    sr_nat_mapping_type type) {

    assert(nat);

    uint16_t proposed_port = aux_int;

    while(true) {

        bool should_rerun = false;

        struct sr_nat_mapping* current = nat->mappings;

        while(current != NULL) {

            if(current->type != type) {
                current = current->next;
                continue;
            }

            if(current->ip_ext != ip_external_interface) {
                current = current->next;
                continue;
            }

            /* ensure proposed_port is not in the NAT table */
            if(current->aux_ext == proposed_port) {
                should_rerun = true;
                break;
            }

            current = current->next;
        }

        if(should_rerun) {
            /* invariant: proposed_port found in table */
            /* generate a random number */

            proposed_port = htons(gen_random_port(type));
            continue;

        } else {
            /* invariant: proposed_port is unique to (ip_external_interface, type) */
            break;
        }

    }

    return proposed_port;

}

/* generate appropriate port based on given mapping type */
uint16_t gen_random_port(sr_nat_mapping_type type) {

    /* seeding RNG */
    srand(time(NULL));

    /* ref: https://liboil.freedesktop.org/documentation/liboil-liboilrandom.html */

    uint16_t proposed_id = (uint16_t)(rand() & 0xffff);

    switch(type) {

    case nat_mapping_icmp:

        /*
            TODO: right?
            Avoid ID == 0
        */
        while(proposed_id == 0) {
            proposed_id = (uint16_t)(rand() & 0xffff);
        }

        break;

    case nat_mapping_tcp:

        /*
            do not use the well-known ports (0-1023)

            ref: https://tools.ietf.org/html/rfc5382#section-7.1
        */
        while(0 <= proposed_id && proposed_id <= 1023) {
            proposed_id = (uint16_t)(rand() & 0xffff);
        }

        break;

    default:
        printf("DEBUG: unexpected sr_nat_mapping_type\n");
        assert(0);
    }

    return proposed_id;
}

bool is_internal_interface(const char* interface) {
    return !strncmp(interface, "eth1", 4);
}

bool is_external_interface(const char* interface) {
    return !strncmp(interface, "eth2", 4);
}

uint16_t get_source_port(const uint8_t* packet, sr_nat_mapping_type map_type) {
    return get_port(packet, map_type, true);
}

uint16_t get_dest_port(const uint8_t* packet, sr_nat_mapping_type map_type) {
    return get_port(packet, map_type, false);
}

uint16_t get_port(const uint8_t* packet, sr_nat_mapping_type map_type, bool get_source) {

    assert(packet);

    if(map_type == nat_mapping_icmp) {

        /* invariant: icmp type is echo */

        /* unwrap_icmp_header */
        uint16_t* identifier = unwrap_icmp_ident(packet);

        return *identifier;

    } else if(map_type == nat_mapping_tcp) {

        sr_tcp_hdr_t* tcp_header = unwrap_tcp_header(packet);

        if(get_source) {
            return tcp_header->src_port;
        } else {
            return tcp_header->dst_port;
        }

    }

    printf("PANIC: unknown map_type\n");
    assert(0);
}

void set_source_address(uint8_t* packet, uint32_t new_source_address) {
    assert(packet);
    sr_ip_hdr_t* ip_header = unwrap_ip_header(packet);
    assert(ip_header);

    ip_header->ip_src = new_source_address;

    recompute_ip_header_checksum(ip_header);
}

void set_source_port(uint8_t* packet, size_t original_packet_size, sr_nat_mapping_type map_type, uint32_t new_src_port) {

    assert(packet);

    if(map_type == nat_mapping_icmp) {

        uint16_t* ident = unwrap_icmp_ident(packet);
        *ident = new_src_port;

        sr_icmp_hdr_t* icmp_header = unwrap_icmp_header(packet);

        size_t icmp_message_size = original_packet_size - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
        recompute_icmp_header_checksum(icmp_header, icmp_message_size);

    } else if(map_type == nat_mapping_tcp) {

        sr_tcp_hdr_t* tcp_header = unwrap_tcp_header(packet);
        tcp_header->src_port = new_src_port;

        /* TODO: recompute checksum */
    } else {

        printf("PANIC: unknown map_type\n");
        assert(0);

    }

    recompute_ip_header_checksum(unwrap_ip_header(packet));
}

void set_dest_address(uint8_t* packet, uint32_t new_dest_address) {
    assert(packet);
    sr_ip_hdr_t* ip_header = unwrap_ip_header(packet);
    assert(ip_header);

    ip_header->ip_dst = new_dest_address;

    recompute_ip_header_checksum(ip_header);
}

void set_dest_port(uint8_t* packet, size_t original_packet_size, sr_nat_mapping_type map_type, uint32_t new_src_port) {

    assert(packet);

    if(map_type == nat_mapping_icmp) {

        uint16_t* ident = unwrap_icmp_ident(packet);
        *ident = new_src_port;

        sr_icmp_hdr_t* icmp_header = unwrap_icmp_header(packet);

        size_t icmp_message_size = original_packet_size - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
        recompute_icmp_header_checksum(icmp_header, icmp_message_size);

    } else if(map_type == nat_mapping_tcp) {

        sr_tcp_hdr_t* tcp_header = unwrap_tcp_header(packet);
        tcp_header->dst_port = new_src_port;

        /* TODO: recompute checksum */
    } else {

        printf("PANIC: unknown map_type\n");
        assert(0);

    }

    recompute_ip_header_checksum(unwrap_ip_header(packet));
}

void print_nat_map(struct sr_nat_mapping* nat_entry) {

    if(nat_entry->type == nat_mapping_icmp) {
        printf("\tnat_entry->type: nat_mapping_icmp\n");
    } else if(nat_entry->type == nat_mapping_tcp) {
        printf("\tnat_entry->type: nat_mapping_tcp\n");
    }

    fprintf(stderr, "\tinternal ip: ");
    print_addr_ip_int(ntohl(nat_entry->ip_int));
    printf("\tinternal port: %d\n", nat_entry->aux_int);

    fprintf(stderr, "\texternal ip: ");
    print_addr_ip_int(ntohl(nat_entry->ip_ext));
    printf("\texternal port: %d\n", nat_entry->aux_ext);

}
