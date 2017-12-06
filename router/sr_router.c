/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance* sr) {
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

    sr_nat_init(&(sr->nat));

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
                     uint8_t* packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("--------------------------\n");

    printf("*** -> Received packet of length %d \n", len);

    /* Ensure ethernet header is of sufficient length */
    if(len < sizeof(sr_ethernet_hdr_t)) {
        printf("Packet did not meet minimum length of Ethernet Header\n");
        return;
    }


    print_hdrs(packet, len);

    switch(ethertype(packet)) {

    case ethertype_ip:

        handle_ip(sr, packet, len, interface);
        break;

    case ethertype_arp:

        handle_arp(sr, packet, len, interface);
        break;

    default:

        printf("\tDEBUG: Dropped packet. Ethernet frame does not contain valid ether type: %" PRIu16 " \n", ethertype(packet));
    }

}/* end sr_ForwardPacket */

bool handle_nat_routing(struct sr_instance* sr,
                        uint8_t* __packet,
                        unsigned int original_packet_size,
                        uint8_t* modified_packet,
                        unsigned int* modified_packet_size,
                        const char* interface/* lent */) {

    assert(sr);
    assert(__packet);
    assert(modified_packet);
    assert(modified_packet_size);

    printf("DEBUG: Handling NAT\n");

    sr_ip_hdr_t* ip_header = unwrap_ip_header(modified_packet);
    uint8_t ip_proto = ip_protocol(ip_header);

    sr_nat_mapping_type map_type;

    if(ip_proto == ip_protocol_icmp) {  /* ICMP */
        map_type = nat_mapping_icmp;
    } else if(ip_proto == ip_protocol_tcp) { /* TCP */
        map_type = nat_mapping_tcp;
    } else {
        printf("DEBUG: IP Protocol not supported for NAT\n");
        return false;
    }

    struct sr_rt *nearest_src = get_route(sr->routing_table, ip_header->ip_src);
    struct sr_rt *nearest_dest = get_route(sr->routing_table, ip_header->ip_dst);

    struct sr_if* external_interface = sr_get_interface(sr, "eth2");
    bool dest_is_nat = (ip_header->ip_dst == external_interface->ip);

    bool src_inside_nat = (nearest_src != NULL) ? (strncmp(nearest_src->interface, "eth1", 4) == 0) :
        false;
    bool dest_inside_nat = (nearest_dest != NULL) ? (strncmp(nearest_dest->interface, "eth1", 4) == 0) :
        false;

    if(nearest_dest == NULL && !dest_is_nat) {
        printf("nearest_dest == NULL\n");
        /* TODO: */
        return false;
    }



    printf("src_inside_nat: %d\n", src_inside_nat);
    printf("dest_inside_nat: %d\n", dest_inside_nat);
    printf("dest_is_nat: %d\n", dest_is_nat);

    if(!src_inside_nat && dest_is_nat) {

        /* packet for inbound */
        printf("NAT: packet for inbound\n");

        uint16_t dest_port = get_dest_port(modified_packet, map_type);

        /* check if mapping exists for external port */
        struct sr_nat_mapping* nat_entry = sr_nat_lookup_external(&(sr->nat), dest_port, map_type);

        if(nat_entry == NULL) {
            /* endpoint independent filtering policy */
            printf("NAT MAP DOES NOT EXIST!!!\n");
            return true;
        }

        printf("\tNAT MAP\n");
        print_nat_map(nat_entry);

        /* Translate dest address/port */

        set_dest_address(modified_packet, nat_entry->ip_int);
        set_dest_port(modified_packet, *modified_packet_size, map_type, nat_entry->aux_int);

        /* TODO: debug */
        /*printf("NEW PACKET: $$$$\n");
        print_hdrs(modified_packet, original_packet_size);*/

        recompute_ip_header_checksum(ip_header);

        return false;

    }

    if (!src_inside_nat && dest_inside_nat) {
        /* drop packet */
        return true;
    }

    if(src_inside_nat && !dest_inside_nat) {

        /* packet for outbound */
        printf("NAT: packet for outbound\n");

        /* TODO: complete */
        uint32_t source_address = ip_header->ip_src;
        uint16_t source_port = get_source_port(modified_packet, map_type);

        uint32_t new_source_address;
        uint16_t new_source_port;

        struct sr_nat_mapping* nat_entry = sr_nat_lookup_internal(&(sr->nat), source_address, source_port, map_type);

        if(nat_entry == NULL) {
            struct sr_nat_mapping* new_nat_entry = sr_nat_insert_mapping(sr, source_address, source_port, map_type);

            printf("\tINSERTED NAT MAP\n");
            print_nat_map(new_nat_entry);

            new_source_address = new_nat_entry->ip_ext;
            new_source_port = new_nat_entry->aux_ext;

        } else {

            new_source_address = nat_entry->ip_ext;
            new_source_port = nat_entry->aux_ext;

            printf("\tNAT MAP\n");
            print_nat_map(nat_entry);

            free(nat_entry);
        }

        /* Translate source address/port */

        set_source_address(modified_packet, new_source_address);
        set_source_port(modified_packet, *modified_packet_size, map_type, new_source_port);

        recompute_ip_header_checksum(ip_header);

        /* TODO: debug */
        /*printf("NEW PACKET: $$$$\n");
        print_hdrs(modified_packet, original_packet_size);*/

        return false;

    }

    recompute_ip_header_checksum(ip_header);

    return false;
}


void translate_inbound(struct sr_instance* sr, uint8_t* packet) {
    /* TODO: */

}

void translate_outbound(struct sr_instance* sr, uint8_t* packet) {
    /* TODO: */

}

void handle_arp(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

    sr_arp_hdr_t* arp_header = unwrap_arp_header(packet);

    if((len - sizeof(sr_ethernet_hdr_t)) < sizeof(arp_header)) {
        printf("Packet did not meet minimum ARP Header length\n");
        return;
    }

    assert(arp_header);

    /* check if router is the intended recipient */
    struct sr_if* this_interface = sr_get_interface(sr, interface);

    if(this_interface == NULL || arp_header->ar_tip != this_interface->ip) {
        /* ARP Target protocol address (TPA) does not match any of router's interfaces */

        printf("WARNING: ARP Target protocol address (TPA) does not match any of router's interfaces\n");

        return;
    }

    assert(this_interface);

    /* Differentiating between ARP request and reply */
    switch(unwrap_arp_op(arp_header)) {

    case arp_op_request:

        handle_arp_request(sr, packet, this_interface, arp_header);
        break;

    case arp_op_reply:

        handle_arp_reply(sr, packet, this_interface, arp_header);
        break;

    default:

        printf("Not a valid ARP op code. Packet dropped.\n");
    }

}

void handle_arp_request(
    struct sr_instance* sr,
    uint8_t* original_packet,
    struct sr_if* source_interface,
    sr_arp_hdr_t* orig_arp_header) {

    /* TODO: printf debug; cleanup */
    printf("ARP Request sent to us.\n");

    assert(sr);
    assert(original_packet);
    assert(source_interface);
    assert(orig_arp_header);

    /* invariant: router is the intended recipient */
    /* NOTE: In an ARP request orig_arp_header->ar_tha is not used */

    /* cache ARP request as necessary */

    struct sr_arpcache* cache_table = &(sr->cache);
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(cache_table, orig_arp_header->ar_sip);

    if(arp_entry == NULL) {
        sr_arpcache_insert(cache_table, orig_arp_header->ar_sha, orig_arp_header->ar_sip);
    }

    if(arp_entry != NULL) {
        if(!is_eth_address_equal(orig_arp_header->ar_sha, arp_entry->mac)) {
            sr_arpcache_insert(cache_table, orig_arp_header->ar_sha, orig_arp_header->ar_sip);
            arp_entry->valid = 0;
        }
    }

    /* Send ARP reply */

    size_t packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* packet = (uint8_t*) malloc(packet_size);

    /* Handle eth header */

    sr_ethernet_hdr_t* orig_eth_header = unwrap_eth_header(original_packet);
    sr_ethernet_hdr_t* eth_header = unwrap_eth_header(packet);

    set_eth_header(
        eth_header,
        orig_eth_header->ether_shost /* dest_address*/,
        source_interface->addr /* source_address */,
        ethertype_arp);

    /* Handle ARP header */

    sr_arp_hdr_t* arp_header = unwrap_arp_header(packet);

    set_arp_header(
        arp_header,
        arp_op_reply,
        source_interface->addr /* sender_hardware_address */,
        &(source_interface->ip) /* sender_ip_address */,
        orig_arp_header->ar_sha /* target_hardware_address */,
        &(orig_arp_header->ar_sip) /* target_ip_address */
    );

    /* send packet */
    sr_send_packet(sr, packet, packet_size, source_interface->name);
    printf("Sent ARP\n");
    /* clean up */

    free(packet);
    free(arp_entry);

}

void handle_arp_reply(
    struct sr_instance* sr,
    uint8_t* packet,
    struct sr_if* this_interface,
    sr_arp_hdr_t* arp_header) {

    assert(sr);
    assert(packet);
    assert(this_interface);
    assert(arp_header);

    /* Check Target hardware address (THA) */
    if(!is_eth_address_equal(arp_header->ar_tha, this_interface->addr)) {
        printf("handle_arp_reply. Target hardware address (THA) does not match with any interfaces\n");
        return;
    }

    printf("ARP Reply sent to us.\n");

    struct sr_arpcache* cache_table = &(sr->cache);

    struct sr_arpreq* arp_request = sr_arpcache_insert(
                                        cache_table,
                                        arp_header->ar_sha,
                                        arp_header->ar_sip);

    if(arp_request == NULL) {
        return;
    }

    /* Flush queued packets waiting for MAC address to be resolved */

    struct sr_packet* current_packet = arp_request->packets;

    while(current_packet != NULL) {

        uint8_t* packet = current_packet->buf;
        assert(packet);
        size_t packet_size = current_packet->len;

        /* Fill in details for eth header */

        sr_ethernet_hdr_t* eth_header = unwrap_eth_header(packet);

        /* Set using outgoing interface */
        assert(current_packet->iface);
        struct sr_if* source_interface = sr_get_interface(sr, current_packet->iface);
        assert(source_interface);
        set_eth_address_with(eth_header->ether_shost, source_interface->addr);

        /* Fill with resolved MAC address */
        set_eth_address_with(eth_header->ether_dhost, arp_header->ar_sha);

        printf("Flushed PACKET: @@@@\n");
        print_hdrs(packet, packet_size);

        /* send packet */
        sr_send_packet(sr, packet, packet_size, source_interface->name);
        printf("Send ARP\n");
        current_packet = current_packet->next;
    }

    sr_arpreq_destroy(cache_table, arp_request);

}

void handle_ip(
    struct sr_instance* sr,
    uint8_t* original_packet,
    unsigned int len,
    char* interface_name) {

    /* TODO: debug */
    printf("Reached IP Handler\n");

    assert(sr);
    assert(original_packet);
    assert(interface_name);

    /*
        Header validation.
        see: https://tools.ietf.org/html/rfc1812#section-5.2.2
     */

    sr_ip_hdr_t* ip_header = unwrap_ip_header(original_packet);
    assert(ip_header);


    /*
        (1) The packet length reported by the Link Layer must be large enough
        to hold the minimum length legal IP datagram (20 bytes). [RFC 1812]
        The router SHOULD verify that the packet length reported by the Link
        Layer is at least as large as the IP total length recorded in the
        packet's IP header.
     */
    if(len < ntohs(ip_header->ip_len)) {
        printf("IP header length too long for frame; dropped packet.\n");
        return;
    }

    /*
        (2) The IP checksum must be correct. [RFC 1812]
     */
    if(!valid_ip_header_checksum(ip_header)) {
        /* TODO: any ICMP??? */
        printf("Invalid IP header checksum; packet dropped.\n");
        return;
    }

    /*
        (3) The IP version number must be 4 [RFC 1812]
     */
    if(ip_header->ip_v != 4) {
        printf("The IP version number must be 4; packet dropped.\n");
        return;
    }

    /* (4) The IP header length field must be large enough to hold the
        minimum length legal IP datagram. The minimum value for this field is 5.
        (20 bytes = 5 words) [RFC 1812] */
    if(ip_header->ip_hl < 5 || (len - sizeof(sr_ethernet_hdr_t)) < sizeof(ip_header)) {
        printf("Packet did not meet minimum IP Header length; packet dropped.\n");
        return;
    }

    /* (5) The IP total length field must be large enough to hold the IP
        datagram header, whose length is specified in the IP header
        length field. */
    /*
    ip_header->ip_len := number of bytes
    ip_header->ip_hl := number of 4 byte words
     */
    if(ntohs(ip_header->ip_len) < (ip_header->ip_hl * 4)) {
        printf("Not enough space to add packet\n");
        return;
    }

    /*
        5.2.3 Local Delivery Decision [RFC 1812]

        When a router receives an IP packet, it must decide whether the
        packet is addressed to the router (and should be delivered locally)
        or the packet is addressed to another system (and should be handled
        by the forwarder).

        ...

        * The packet is delivered locally and not considered for forwarding
            in the following cases:

            - The packet's destination address exactly matches one of the
                router's IP addresses,

        ...

    */

    unsigned int modified_packet_size = len;
    uint8_t* modified_packet = (uint8_t*)malloc(modified_packet_size);
    assert(modified_packet);
    memcpy(modified_packet, original_packet, modified_packet_size);

    /* If NAT was enabled, change the IP addresses of the packet and return*/
    if(sr->nat_enabled == 1) {
        bool should_drop = handle_nat_routing(sr, original_packet, len, modified_packet, &modified_packet_size, interface_name);

        if(should_drop) {
            printf("DEBUG: packet dropped\n");
            return;
        }
    }

    ip_header = unwrap_ip_header(modified_packet);
    assert(ip_header);

    struct sr_if* router_interface = sr_get_interface_by_ip(sr, ip_header->ip_dst);

    if(router_interface != NULL) {

        /* packet not considered for forwarding */

        printf("DEBUG: IP Packet destined for router.\n");

        handle_ip_local(sr, interface_name, original_packet, len, ip_header);


    } else {

        /* packet considered for forwarding */

        printf("DEBUG: IP Packet to be forwarded.\n");

        /* TODO: Alberto: code review */
        /* TODO: TEMP LINE WHILE TABLE IS BEING BUILT */
        /*if(sr->nat_enabled) {
            handle_tcp(sr, original_packet, len, interface_name);
        }*/

        handle_ip_forward(sr, interface_name, original_packet, len, modified_packet, &modified_packet_size);

    }

    /* clean up */
    free(modified_packet);

    printf("=======================================================\n");

}

void handle_ip_local(
    struct sr_instance* sr,
    char* interface_name, /* interface where packet came through */
    uint8_t* original_packet,
    unsigned int original_packet_size,
    sr_ip_hdr_t* ip_header) {

    assert(sr);
    assert(interface_name);
    assert(original_packet);
    assert(ip_header);

    /*
    INVARIANT: ip_header->ip_dst IS one of the router's interfaces
     */

    switch(ip_header->ip_p) {

    case ip_protocol_icmp:

        icmp_echo(sr, interface_name, original_packet, original_packet_size);
        break;

    case ip_protocol_tcp:

        if(sr->nat_enabled) {

            /* NAT Behavioral Requirements for TCP */

            /* TODO: Alberto review */

            /*handle_tcp(sr, original_packet, original_packet_size, interface_name);
            return;*/

        }

        /* Regular behaviour when NAT is not enabled */

    case ip_protocol_udp:
        /*
            5.2.7.1 Destination Unreachable [RFC 1812]
            see: https://tools.ietf.org/html/rfc1812#section-5.2.7.1
        */

        /*
            Port unreachable error (code = 3)
            (the designated protocol is unable to inform the host of the incoming message).
        */

        icmp_dest_unreachable(sr, original_packet, interface_name, 3);
        break;

    default:

        /* TODO: what to do??????? */
        printf("Unknown ip_header->ip_p\n");
    }

}

/* TODO: Alberto: code review*/
void handle_tcp(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    printf("This is a TCP packet!\n");

    size_t offset = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t); /* TCP is payload of IP */
    print_hdr_tcp(packet + offset);

    /* Unwrap headers */
    sr_tcp_hdr_t* tcp_hdr = unwrap_tcp_header(packet);
    sr_ip_hdr_t* ip_hdr = unwrap_ip_header(packet);

    /* Verify checksum
    if(!valid_tcp_header_checksum(tcp_hdr, offset)){
        printf("Invalid TCP header checksum; packet dropped.\n");
        return;
    } */

    struct sr_if* outgoing_interface = sr_get_interface(sr, interface);

    /* Switch source and destination ports and get the size of the TCP packet */
    uint8_t src_port = tcp_hdr->dst_port;
    uint8_t dst_port = tcp_hdr->src_port;

    /* Set headers with appropriate fields */
    set_tcp_header(tcp_hdr, ip_hdr, src_port, dst_port, offset);
    sr_send_packet(sr, packet, len, outgoing_interface->name);

}

void icmp_echo(
    struct sr_instance* sr,
    char* interface_name, /* interface where packet came through */
    uint8_t* original_packet,
    unsigned int original_packet_size) {

    /* Obtain ICMP packet */
    sr_icmp_hdr_t* original_icmp_header = unwrap_icmp_header(original_packet);
    size_t icmp_message_size = original_packet_size - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);

    /* Compute checksum */
    if(!valid_icmp_header_checksum(original_icmp_header, icmp_message_size)) {
        printf("Invalid ICMP header checksum; drop packet\n");
        return;
    }

    struct sr_if* this_interface = sr_get_interface(sr, interface_name);

    size_t packet_size = original_packet_size;

    uint8_t* packet = (uint8_t*) malloc(packet_size);

    memcpy(packet, original_packet, original_packet_size);

    /* Fill in details for eth header */
    sr_ethernet_hdr_t* orig_eth_header = unwrap_eth_header(original_packet);

    sr_ethernet_hdr_t* eth_header = unwrap_eth_header(packet);

    set_eth_header(
        eth_header,
        orig_eth_header->ether_shost /* dest_address*/,
        this_interface->addr /* source_address */,
        ethertype_ip);

    /* Fill in details for IP header */
    sr_ip_hdr_t* orig_ip_header = unwrap_ip_header(original_packet);

    sr_ip_hdr_t* ip_header = unwrap_ip_header(packet);

    uint32_t source_ip_address = orig_ip_header->ip_dst;

    uint32_t dest_ip_address = orig_ip_header->ip_src;

    set_ip_header(
        ip_header,
        icmp_message_size,
        ip_protocol_icmp,
        source_ip_address,
        dest_ip_address);

    /* Fill in details for ICMP echo */

    sr_icmp_hdr_t* icmp_header = unwrap_icmp_header(packet);

    set_icmp_header(
        icmp_header,
        0 /* icmp_type. 0 for echo reply message. */,
        0 /* icmp_code */,
        icmp_message_size /* size of entire icmp message (header + data) */
    );

    printf("--------\n");

    printf("ECHO:\n");

    print_hdrs(packet, packet_size);

    /*
        Find MAC address via ARP
    */

    struct sr_arpcache* cache_table = &(sr->cache);

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(cache_table, ip_header->ip_dst);

    if(arp_entry == NULL) {

        /* ARP cache miss */

        struct sr_arpreq* arp_request = sr_arpcache_queuereq(
                                            cache_table,
                                            ip_header->ip_dst,
                                            packet,
                                            packet_size,
                                            this_interface->name);

        handle_arpreq(sr, arp_request);

        return;
    }

    /* ARP cache hit; send packet */

    sr_send_packet(sr, packet, packet_size, this_interface->name);
    printf("Send ICMP\n");
    /* clean up */
    free(packet);
    free(arp_entry);

}

void handle_ip_forward(
    struct sr_instance* sr,
    char* interface_name, /* interface where packet came through */
    uint8_t* __original_packet,
    unsigned int __original_packet_size,
    uint8_t* modified_packet,
    unsigned int* modified_packet_size) {

    assert(sr);
    assert(interface_name);
    assert(__original_packet);
    assert(modified_packet);
    assert(modified_packet_size);

    sr_ip_hdr_t* ip_header = unwrap_ip_header(modified_packet);
    assert(ip_header);

    /*
    INVARIANT: ip_header->ip_dst is NOT one of the router's interfaces
     */

    /*
        [RFC 1812]

        ...

        When a router forwards a packet, it MUST reduce the TTL by at least
        one.

        ...

        If the TTL is reduced to zero (or less), the packet MUST be
        discarded, and if the destination is not a multicast address the
        router MUST send an ICMP Time Exceeded message, Code 0 (TTL Exceeded
        in Transit) message to the source.

        see: https://tools.ietf.org/html/rfc1812#section-5.3.1
     */

    ip_header->ip_ttl -= 1;

    if(ip_header->ip_ttl <= 0) {
        printf("IP Header lifespan expired. Dropping packet.\n");
        icmp_time_exceeded(sr, __original_packet, interface_name);
        return;
    }

    recompute_ip_header_checksum(ip_header);

    /*
        5.2.4.3 Next Hop Address [RFC 1812]
        see: https://tools.ietf.org/html/rfc1812#section-5.2.4.3
    */

    uint32_t ip_packet_destination = ip_header->ip_dst;
    struct sr_rt* next_hop = get_route(sr->routing_table, ip_packet_destination);

    if(next_hop == NULL) {

        /*
            5.2.7.1 Destination Unreachable [RFC 1812]
            see: https://tools.ietf.org/html/rfc1812#section-5.2.7.1
        */

        /* Network unreachable error. icmp_code = 0 */
        printf("\t\t\t\thandle_ip_forward:icmp_dest_unreachable\n");
        /* TODO: right interface_name?*/
        icmp_dest_unreachable(sr, __original_packet, interface_name, 0);

        return;
    }

    /*
        Find MAC address of gateway
        (the node that is assumed to know how to forward packets on to other networks)
    */

    struct sr_arpcache* cache_table = &(sr->cache);
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(cache_table, next_hop->gw.s_addr);

    if(arp_entry == NULL) {

        /* ARP cache miss */

        struct sr_arpreq* arp_request = sr_arpcache_queuereq(
                                            cache_table,
                                            next_hop->dest.s_addr,
                                            modified_packet,
                                            *modified_packet_size,
                                            next_hop->interface);

        handle_arpreq(sr, arp_request);

        return;
    }

    /* ARP cache hit */

    /* Update eth header */

    sr_ethernet_hdr_t* eth_header = unwrap_eth_header(modified_packet);

    struct sr_if* outgoing_interface = sr_get_interface(sr, next_hop->interface);

    set_eth_address_with(eth_header->ether_shost, outgoing_interface->addr);
    set_eth_address_with(eth_header->ether_dhost, arp_entry->mac);

    printf("SENT PACKET: @@@@\n");
    print_hdrs(modified_packet, *modified_packet_size);

    sr_send_packet(sr, modified_packet, *modified_packet_size, next_hop->interface);
    /* clean up */

    /* allocated by sr_arpcache_lookup */
    free(arp_entry);

}

void icmp_dest_unreachable(
    struct sr_instance* sr,
    uint8_t* original_packet,
    char* interface_name /* interface from which this ICMP will be sent from */,
    uint8_t icmp_code) {

    assert(sr);
    assert(original_packet);
    assert(interface_name);

    struct sr_if* this_interface = sr_get_interface(sr, interface_name);

    size_t packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t* packet = (uint8_t*) malloc(packet_size);

    /* Fill in details for eth header */

    sr_ethernet_hdr_t* orig_eth_header = unwrap_eth_header(original_packet);
    sr_ethernet_hdr_t* eth_header = unwrap_eth_header(packet);

    set_eth_header(
        eth_header,
        orig_eth_header->ether_shost /* dest_address*/,
        this_interface->addr /* source_address */,
        ethertype_ip);

    /* Fill in details for IP header */

    sr_ip_hdr_t* orig_ip_header = unwrap_ip_header(original_packet);
    sr_ip_hdr_t* ip_header = unwrap_ip_header(packet);

    uint32_t source_ip_address;

    switch(icmp_code) {

    case 0: /* Network unreachable error. */
    case 1: /* Host unreachable error. */

        source_ip_address = this_interface->ip;
        break;

    case 3: /* Port unreachable error
               (the designated protocol is unable to inform the host of the incoming message). */

        source_ip_address = orig_ip_header->ip_dst;
        break;

    default:
        /* only above codes are supported as per assignment requirements */
        printf("icmp_dest_unreachable warning: %d\n", icmp_code);
        assert(0);
    }

    uint32_t dest_ip_address = orig_ip_header->ip_src;

    set_ip_header(
        ip_header,
        sizeof(sr_icmp_t3_hdr_t), /* payload_size */
        ip_protocol_icmp,
        source_ip_address,
        dest_ip_address);

    /* Fill in details for ICMP */

    sr_icmp_t3_hdr_t* icmp_header = unwrap_icmp_t3_header(packet);

    set_icmp_t3_header(
        icmp_header,
        icmp_code,
        orig_ip_header
    );

    /* send packet */

    printf("icmp_dest_unreachable PACKET: @@@@\n");
    print_hdrs(packet, packet_size);

    sr_send_packet(sr, packet, packet_size, this_interface->name);

    /* clean up */

    free(packet);
}

void icmp_time_exceeded(struct sr_instance* sr, uint8_t* original_packet, char* interface_name) {

    assert(sr);
    assert(original_packet);
    assert(interface_name);

    struct sr_if* this_interface = sr_get_interface(sr, interface_name);

    size_t packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t* packet = (uint8_t*) malloc(packet_size);

    /* Fill in details for eth header */

    sr_ethernet_hdr_t* orig_eth_header = unwrap_eth_header(original_packet);
    sr_ethernet_hdr_t* eth_header = unwrap_eth_header(packet);

    set_eth_header(
        eth_header,
        orig_eth_header->ether_shost /* dest_address*/,
        this_interface->addr /* source_address */,
        ethertype_ip);

    /* Fill in details for IP header */

    sr_ip_hdr_t* orig_ip_header = unwrap_ip_header(original_packet);
    sr_ip_hdr_t* ip_header = unwrap_ip_header(packet);

    uint32_t source_ip_address = this_interface->ip;
    uint32_t dest_ip_address = orig_ip_header->ip_src;

    set_ip_header(
        ip_header,
        sizeof(sr_icmp_t11_hdr_t),
        ip_protocol_icmp,
        source_ip_address,
        dest_ip_address);

    /* Fill in details for ICMP */

    sr_icmp_t11_hdr_t* icmp_header = unwrap_icmp_t11_header(packet);

    set_icmp_t11_header(
        icmp_header,
        0 /* icmp_code. Time-to-live exceeded in transit. */,
        orig_ip_header
    );

    /* send packet */

    sr_send_packet(sr, packet, packet_size, this_interface->name);

    /* clean up */

    free(packet);

}
