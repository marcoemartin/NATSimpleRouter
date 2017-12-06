/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance {
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    unsigned short topo_id;

    /* NAT options */
    unsigned int nat_enabled;

    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    struct sr_nat nat; /* NAT */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance*, uint8_t*, unsigned int , const char*);
int sr_connect_to_server(struct sr_instance*, unsigned short , char*);
int sr_read_from_server(struct sr_instance*);

/* -- sr_router.c -- */
void sr_init(struct sr_instance*);

void sr_handlepacket(struct sr_instance*, uint8_t*, unsigned int , char*);

bool handle_nat_routing(struct sr_instance* sr,
                        uint8_t* original_packet,
                        unsigned int original_packet_size,
                        uint8_t* modified_packet,
                        unsigned int* modified_packet_size,
                        const char* interface/* lent */);

void handle_ip(
    struct sr_instance* sr,
    uint8_t* original_packet,
    unsigned int len,
    char* interface_name);

void handle_ip_local(
    struct sr_instance* sr,
    char* interface_name, /* interface where packet came through */
    uint8_t* original_packet,
    unsigned int original_packet_size,
    sr_ip_hdr_t* ip_header);

void handle_ip_forward(
    struct sr_instance* sr,
    char* interface_name, /* interface where packet came through */
    uint8_t* original_packet,
    unsigned int original_packet_size,
    uint8_t* modified_packet,
    unsigned int* modified_packet_size);

void handle_arp(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);

void handle_arp_request(
    struct sr_instance* sr,
    uint8_t* original_packet,
    struct sr_if* source_interface,
    sr_arp_hdr_t* orig_arp_header);

void handle_arp_reply(
    struct sr_instance* sr,
    uint8_t* packet,
    struct sr_if* this_interface,
    sr_arp_hdr_t* arp_header);

void icmp_dest_unreachable(
    struct sr_instance* sr,
    uint8_t* original_packet,
    char* interface_name /* interface from which this ICMP will be sent from */,
    uint8_t icmp_code);

void icmp_time_exceeded(struct sr_instance* sr, uint8_t* original_packet, char* interface_name);
void handle_tcp(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);

void icmp_echo(
    struct sr_instance* sr,
    char* interface_name, /* interface where packet came through */
    uint8_t* original_packet,
    unsigned int original_packet_size);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance*, const char*);
void sr_set_ether_ip(struct sr_instance*, uint32_t);
void sr_set_ether_addr(struct sr_instance*, const unsigned char*);
void sr_print_if_list(struct sr_instance*);


#endif /* SR_ROUTER_H */
