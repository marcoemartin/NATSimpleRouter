/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SR_BOOL_H
#define SR_BOOL_H

/* source: http://stackoverflow.com/a/1921557/412627 */
typedef enum { false, true } bool;

#endif


#ifndef SR_UTILS_H
#define SR_UTILS_H

sr_ethernet_hdr_t* unwrap_eth_header(const uint8_t* packet);
sr_ip_hdr_t* unwrap_ip_header(const uint8_t* packet);
sr_arp_hdr_t* unwrap_arp_header(const uint8_t* packet);
sr_icmp_hdr_t* unwrap_icmp_header(const uint8_t* packet);
uint16_t* unwrap_icmp_ident(const uint8_t* packet);
sr_icmp_t3_hdr_t* unwrap_icmp_t3_header(const uint8_t* packet);
sr_icmp_t11_hdr_t* unwrap_icmp_t11_header(const uint8_t* packet);
sr_tcp_hdr_t* unwrap_tcp_header(const uint8_t* packet);

uint16_t unwrap_arp_op(sr_arp_hdr_t* arp_header);

void fill_octets_with(uint8_t* address, size_t len, uint8_t default_value);

void set_ethertype(sr_ethernet_hdr_t* eth_header, enum sr_ethertype ethertype);
void set_eth_address_with(unsigned char* dest_address, const unsigned char* source_address);
bool is_eth_address_equal(const unsigned char* dest_address, const unsigned char* source_address);
void set_eth_header(
    sr_ethernet_hdr_t* eth_header,
    const unsigned char* dest_address,
    const unsigned char* source_address,
    enum sr_ethertype ether_type);

void set_arp_header(
    sr_arp_hdr_t* arp_header,
    enum sr_arp_opcode operation,
    const unsigned char* sender_hardware_address,
    const uint32_t* sender_ip_address,
    const unsigned char* target_hardware_address,
    const uint32_t* target_ip_address
);

void set_ip_header(
    sr_ip_hdr_t* ip_header,
    size_t payload_size,
    enum sr_ip_protocol protocol,
    uint32_t source_address,
    uint32_t dest_address
);

void set_tcp_header(
    sr_tcp_hdr_t* tcp_header,
    sr_ip_hdr_t* ip_header,
    uint32_t source_port,
    uint32_t dest_port,
    size_t tcp_size
);

bool valid_icmp_header_checksum(sr_icmp_hdr_t* icmp_header, size_t icmp_message_size);
bool valid_tcp_header_checksum(sr_tcp_hdr_t*, size_t);
bool valid_ip_header_checksum(sr_ip_hdr_t* ip_header);
void recompute_ip_header_checksum(sr_ip_hdr_t* ip_header);
void recompute_icmp_header_checksum(sr_icmp_hdr_t* icmp_header, size_t icmp_size);

void set_icmp_header(
    sr_icmp_hdr_t* icmp_header,
    uint8_t icmp_type,
    uint8_t icmp_code,
    size_t icmp_size /* size of entire icmp message (header + data) */
);
void set_icmp_t3_header(sr_icmp_t3_hdr_t* icmp_t3_header, uint8_t icmp_code, sr_ip_hdr_t* ip_header);
void set_icmp_t11_header(sr_icmp_t11_hdr_t* icmp_t11_header, uint8_t icmp_code, sr_ip_hdr_t* ip_header);

uint16_t cksum(const void* _data, int len);

uint16_t ethertype(uint8_t* buf);
uint8_t ip_protocol(sr_ip_hdr_t* iphdr);

void print_addr_eth(uint8_t* addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t* buf);
void print_hdr_ip(uint8_t* buf);
void print_hdr_icmp(uint8_t* buf);
void print_hdr_arp(uint8_t* buf);
void print_hdr_tcp(uint8_t* buf)
;
/* prints all headers, starting from eth */
void print_hdrs(uint8_t* buf, uint32_t length);

#endif /* -- SR_UTILS_H -- */
