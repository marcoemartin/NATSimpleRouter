#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include <inttypes.h>

sr_ethernet_hdr_t* unwrap_eth_header(const uint8_t* packet) {
    assert(packet != NULL);
    return (sr_ethernet_hdr_t*) packet;
}

sr_ip_hdr_t* unwrap_ip_header(const uint8_t* packet) {
    assert(packet != NULL);
    return (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
}

sr_arp_hdr_t* unwrap_arp_header(const uint8_t* packet) {
    assert(packet != NULL);
    return (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
}

sr_icmp_hdr_t* unwrap_icmp_header(const uint8_t* packet) {
    assert(packet != NULL);
    return (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

uint16_t* unwrap_icmp_ident(const uint8_t* packet) {
    assert(packet != NULL);

    return (uint16_t*)(
        packet +
        sizeof(sr_ethernet_hdr_t) +
        sizeof(sr_ip_hdr_t) +
        sizeof(uint8_t) /* type */ +
        sizeof(uint8_t) /* code */ +
        sizeof(uint16_t) /* checksum*/);
}

sr_icmp_t3_hdr_t* unwrap_icmp_t3_header(const uint8_t* packet) {
    assert(packet != NULL);
    return (sr_icmp_t3_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

sr_icmp_t11_hdr_t* unwrap_icmp_t11_header(const uint8_t* packet) {
    assert(packet != NULL);
    return (sr_icmp_t11_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

uint16_t unwrap_arp_op(sr_arp_hdr_t* arp_header) {
    assert(arp_header);
    return ntohs(arp_header->ar_op);
}

sr_tcp_hdr_t* unwrap_tcp_header(const uint8_t* packet) {
    assert(packet != NULL);
    return (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

void fill_octets_with(uint8_t* address, size_t len, uint8_t default_value) {

    assert(address);

    size_t pos = 0;

    for(; pos < len; pos++) {
        address[pos] = default_value;
    }
}

void set_ethertype(sr_ethernet_hdr_t* eth_header, enum sr_ethertype ether_type) {
    assert(eth_header);
    eth_header->ether_type = htons(ether_type);
}

void set_eth_address_with(unsigned char* dest_address, const unsigned char* source_address) {
    assert(dest_address);
    assert(source_address);
    memcpy(dest_address, source_address, sizeof(unsigned char) * ETHER_ADDR_LEN);
}

bool is_eth_address_equal(const unsigned char* dest_address, const unsigned char* source_address) {

    assert(dest_address);
    assert(source_address);

    int pos = ETHER_ADDR_LEN;

    while(pos -- > 0) {
        if(dest_address[pos] != source_address[pos]) {
            return false;
        }
    }

    return true;
}

void set_eth_header(
    sr_ethernet_hdr_t* eth_header,
    const unsigned char* dest_address,
    const unsigned char* source_address,
    enum sr_ethertype ether_type) {

    assert(eth_header);

    if(dest_address != NULL) {
        set_eth_address_with(eth_header->ether_dhost, dest_address);
    }

    if(source_address != NULL) {
        set_eth_address_with(eth_header->ether_shost, source_address);
    }

    /* indicate which protocol is encapsulated in the payload of the frame */
    set_ethertype(eth_header, ether_type);

}

void set_arp_header(
    sr_arp_hdr_t* arp_header,
    enum sr_arp_opcode operation,
    const unsigned char* sender_hardware_address,
    const uint32_t* sender_ip_address,
    const unsigned char* target_hardware_address,
    const uint32_t* target_ip_address
) {

    assert(arp_header);

    /* Hardware type (HTYPE) */
    arp_header->ar_hrd = htons(arp_hrd_ethernet);

    /* Protocol type (PTYPE) */
    arp_header->ar_pro = htons(ethertype_ip);

    /* Hardware length (HLEN) */
    arp_header->ar_hln = ETHER_ADDR_LEN;

    /* Protocol length (PLEN); IPv4 address size is 4 octets */
    arp_header->ar_pln = 4;

    /*
        Operation.
        Specifies the operation that the sender is performing:
        1 for request, 2 for reply.
    */
    arp_header->ar_op = htons(operation);


    /* Sender hardware address (SHA) */
    if(sender_hardware_address != NULL) {
        set_eth_address_with(arp_header->ar_sha, sender_hardware_address);
    }

    /* Sender protocol address (SPA) */
    if(sender_ip_address != NULL) {
        arp_header->ar_sip = *sender_ip_address;
    }

    /* Target hardware address (THA) */
    if(target_hardware_address != NULL) {
        /* NOTE: this field is ignored for ARP requests */
        set_eth_address_with(arp_header->ar_tha, target_hardware_address);
    }

    /* Target protocol address (TPA) */
    if(target_ip_address != NULL) {
        arp_header->ar_tip = *target_ip_address;
    }

}

void set_ip_header(
    sr_ip_hdr_t* ip_header,
    size_t payload_size,
    enum sr_ip_protocol protocol,
    uint32_t source_address,
    uint32_t dest_address
) {

    /* NOTE: payload_size does not include size of IP header */

    assert(ip_header);

    /* Version. For IPv4, this is always equal to 4. */
    ip_header->ip_v = 4;

    /*
        Internet Header Length (IHL).
        This is the number of four byte (32-bit) “words” at the beginning of the IP packet
    */
    ip_header->ip_hl = sizeof(sr_ip_hdr_t) / 4;

    /*
        Type of service (ToS).
        Not used; set to 0.

        Deprecated; see:  RFC 2474.

        See: https://piazza.com/class/it0h3m8ljm37mb?cid=182
        */
    ip_header->ip_tos = 0;

    /* Total Length. This 16-bit field defines the entire packet size, including header and data, in bytes. */
    ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + payload_size);

    /*
        Identification.
        Not used; see: https://piazza.com/class/it0h3m8ljm37mb?cid=181
    */
    ip_header->ip_id = 0;

    /*
        Flags +  Fragment Offset

        Flags => don't fragment
        Fragment offset => 0

        IP_DF := 0x4000 == 100000000000000_2

        |------------------|
        |  byte 1 | byte 2 |
        |---------|--------|
        |Flag| Fragment    |
        |    | Offset      |
        |----|----|--------|
        |0100|0000|00000000|
        |------------------|
    */
    ip_header->ip_off = htons(IP_DF);


    /*
        Time To Live (TTL).

        TTL = 64
        as defined by RFC 1340

        see: https://tools.ietf.org/html/rfc1340#page-32
    */
    ip_header->ip_ttl = 64;

    /*
        Protocol.
        This field defines the protocol used in the data portion of the IP datagram.
     */
    ip_header->ip_p = protocol;

    ip_header->ip_src = source_address;
    ip_header->ip_dst = dest_address;

    /*
        Checksum.
        For purposes of computing the checksum, the value of the checksum field is zero.

        Byte order independent as per RFC 1071,
        see: https://tools.ietf.org/html/rfc1071
    */
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

}

void set_tcp_header(
    sr_tcp_hdr_t* tcp_header,
    sr_ip_hdr_t* ip_header,
    uint32_t source_port,
    uint32_t dest_port,
    size_t tcp_size
) {

    assert(tcp_header);
    assert(sizeof(sr_tcp_hdr_t) <= tcp_size);

    tcp_header->src_port = source_port;
    tcp_header->dst_port = dest_port;

    /*
        Checksum.

        Byte order independent as per RFC 1071,
        see: https://tools.ietf.org/html/rfc1071
     */
    pseudo_tcp_hdr_t* pseudo_hdr = malloc(sizeof(pseudo_tcp_hdr_t));
    pseudo_hdr->ip_src = ip_header->ip_src;
    pseudo_hdr->ip_dst = ip_header->ip_dst;
    pseudo_hdr->ip_p = ip_header->ip_p;
    pseudo_hdr->data_rsv = 0;
    pseudo_hdr->tcp_len = tcp_size;

    /* Free space for TCP packet + pseudo_tcp_hdr */
    uint8_t* tcp_cksum_fields = (uint8_t*)malloc(tcp_size + sizeof(pseudo_tcp_hdr_t));

    /* Copy the pseudo tcp hdr and the tcp header */
    tcp_cksum_fields = memcpy(tcp_cksum_fields, pseudo_hdr, sizeof(pseudo_tcp_hdr_t));
    tcp_cksum_fields = memcpy(tcp_cksum_fields + sizeof(pseudo_hdr), tcp_header, tcp_size);

    /* Insert new checksum into TCP */
    tcp_header->checksum = 0;
    tcp_header->checksum = cksum(tcp_cksum_fields, sizeof(tcp_size + sizeof(pseudo_tcp_hdr_t)));
}

bool valid_icmp_header_checksum(sr_icmp_hdr_t* icmp_header, size_t icmp_message_size) {

    uint16_t expected_checksum = icmp_header->icmp_sum;

    icmp_header->icmp_sum = 0;
    uint16_t actual_checksum = cksum(icmp_header, icmp_message_size);

    bool result = expected_checksum == actual_checksum;

    /* restore */
    icmp_header->icmp_sum = expected_checksum;

    return result;
}

bool valid_tcp_header_checksum(sr_tcp_hdr_t* tcp_header, size_t tcp_message_size) {

    uint16_t expected_checksum = tcp_header->checksum;

    tcp_header->checksum = 0;
    uint16_t actual_checksum = cksum(tcp_header, tcp_message_size);

    bool result = expected_checksum == actual_checksum;

    /* restore */
    tcp_header->checksum = expected_checksum;

    return result;
}
bool valid_ip_header_checksum(sr_ip_hdr_t* ip_header) {

    uint16_t expected_checksum = ip_header->ip_sum;

    ip_header->ip_sum = 0;
    uint16_t actual_checksum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    bool result = expected_checksum == actual_checksum;

    /* restore */
    ip_header->ip_sum = expected_checksum;

    return result;
}

void recompute_ip_header_checksum(sr_ip_hdr_t* ip_header) {
    ip_header->ip_sum = 0;
    uint16_t result_checksum = cksum(ip_header, sizeof(sr_ip_hdr_t));
    ip_header->ip_sum = result_checksum;
}

void recompute_icmp_header_checksum(sr_icmp_hdr_t* icmp_header, size_t icmp_size) {
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header, icmp_size);
}

void set_icmp_header(
    sr_icmp_hdr_t* icmp_header,
    uint8_t icmp_type,
    uint8_t icmp_code,
    size_t icmp_size /* size of entire icmp message (header + data) */
) {

    assert(icmp_header);
    assert(sizeof(sr_icmp_hdr_t) <= icmp_size);

    icmp_header->icmp_type = icmp_type;
    icmp_header->icmp_code = icmp_code;

    /*
        Checksum.

        Byte order independent as per RFC 1071,
        see: https://tools.ietf.org/html/rfc1071
     */
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header, icmp_size);
}

void set_icmp_t3_header(sr_icmp_t3_hdr_t* icmp_t3_header, uint8_t icmp_code, sr_ip_hdr_t* ip_header) {

    assert(icmp_t3_header);

    icmp_t3_header->icmp_type = 3;

    switch(icmp_code) {

    case 0: /* Network unreachable error. */
    case 1: /* Host unreachable error. */
    case 3: /* Port unreachable error
               (the designated protocol is unable to inform the host of the incoming message). */
        break;

    default:
        /* only above codes are supported as per assignment requirements */
        printf("set_icmp_t3_header warning: %d\n", icmp_code);
        assert(0);
    }

    icmp_t3_header->icmp_code = icmp_code;

    icmp_t3_header->unused = 0;

    /* Only used when icmp_code := 4 */
    icmp_t3_header->next_mtu = 0;

    memcpy(icmp_t3_header->data, ip_header, sizeof(uint8_t) * ICMP_DATA_SIZE);

    /*
        Checksum.

        Byte order independent as per RFC 1071,
        see: https://tools.ietf.org/html/rfc1071
     */
    icmp_t3_header->icmp_sum = 0;
    icmp_t3_header->icmp_sum = cksum(icmp_t3_header, sizeof(sr_icmp_t3_hdr_t));
}

void set_icmp_t11_header(sr_icmp_t11_hdr_t* icmp_t11_header, uint8_t icmp_code, sr_ip_hdr_t* ip_header) {

    assert(icmp_t11_header);

    icmp_t11_header->icmp_type = 11;

    switch(icmp_code) {

    case 0: /*  0 = time to live exceeded in transit; */
    case 1: /*  1 = fragment reassembly time exceeded. */
        break;

    default:
        printf("invalid icmp_code for set_icmp_t11_header: %d\n", icmp_code);
        assert(0);
    }

    icmp_t11_header->icmp_code = icmp_code;

    icmp_t11_header->unused = 0;

    memcpy(icmp_t11_header->data, ip_header, sizeof(uint8_t) * ICMP_DATA_SIZE);

    /*
        Checksum.

        Byte order independent as per RFC 1071,
        see: https://tools.ietf.org/html/rfc1071
     */
    icmp_t11_header->icmp_sum = 0;
    icmp_t11_header->icmp_sum = cksum(icmp_t11_header, sizeof(sr_icmp_t11_hdr_t));

}

uint16_t cksum(const void* _data, int len) {
    const uint8_t* data = _data;
    uint32_t sum;

    for(sum = 0; len >= 2; data += 2, len -= 2) {
        sum += data[0] << 8 | data[1];
    }

    if(len > 0) {
        sum += data[0] << 8;
    }

    while(sum > 0xffff) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    sum = htons(~sum);
    return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t* buf) {
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)buf;
    return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(sr_ip_hdr_t* iphdr) {
    return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t* addr) {
    int pos = 0;
    uint8_t cur;

    for(; pos < ETHER_ADDR_LEN; pos++) {
        cur = addr[pos];

        if(pos > 0) {
            fprintf(stderr, ":");
        }

        fprintf(stderr, "%02X", cur);
    }

    fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
    char buf[INET_ADDRSTRLEN];

    if(inet_ntop(AF_INET, &address, buf, 100) == NULL) {
        fprintf(stderr, "inet_ntop error on address conversion\n");

    } else {
        fprintf(stderr, "%s\n", buf);
    }
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
    uint32_t curOctet = ip >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 8) >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 16) >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 24) >> 24;
    fprintf(stderr, "%d\n", curOctet);
}

/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t* buf) {
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)buf;
    fprintf(stderr, "ETHERNET header:\n");
    fprintf(stderr, "\tdestination: ");
    print_addr_eth(ehdr->ether_dhost);
    fprintf(stderr, "\tsource: ");
    print_addr_eth(ehdr->ether_shost);
    fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t* buf) {
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(buf);
    fprintf(stderr, "IP header:\n");
    fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
    fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
    fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
    fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
    fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

    if(ntohs(iphdr->ip_off) & IP_DF) {
        fprintf(stderr, "\tfragment flag: DF\n");

    } else if(ntohs(iphdr->ip_off) & IP_MF) {
        fprintf(stderr, "\tfragment flag: MF\n");

    } else if(ntohs(iphdr->ip_off) & IP_RF) {
        fprintf(stderr, "\tfragment flag: R\n");
    }

    fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
    fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
    fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

    /*Keep checksum in NBO*/
    fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

    fprintf(stderr, "\tsource: ");
    print_addr_ip_int(ntohl(iphdr->ip_src));

    fprintf(stderr, "\tdestination: ");
    print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out fields in IP header. */
void print_hdr_tcp(uint8_t* buf) {
    sr_tcp_hdr_t* tcphdr = (sr_tcp_hdr_t*)(buf);
    fprintf(stderr, "TCP header:\n");
    fprintf(stderr, "\tSource: %d\n", ntohs(tcphdr->src_port));
    fprintf(stderr, "\tDestination: %d\n", ntohs(tcphdr->dst_port));
    fprintf(stderr, "\tSequence number: %" PRIu32 "\n", ntohl(tcphdr->seq_num));
    fprintf(stderr, "\tAcknowledgment number: %d\n", ntohl(tcphdr->ack_num));

    /* Translate the flag and print */
    if(tcphdr->flags & TCP_FIN) {
        fprintf(stderr, "\tFlags: FIN\n");

    } else if(tcphdr->flags & TCP_SYN) {
        fprintf(stderr, "\tFlags: SYN\n");

    } else if(tcphdr->flags & TCP_RST) {
        fprintf(stderr, "\tFlag: RST\n");

    } else if(tcphdr->flags & TCP_PSH) {
        fprintf(stderr, "\tFlags: PSH\n");

    } else if(tcphdr->flags & TCP_ACK) {
        fprintf(stderr, "\tFlags: ACK\n");

    } else if(tcphdr->flags & TCP_URG) {
        fprintf(stderr, "\tFlags: URG\n");

    } else if(tcphdr->flags & TCP_ECE) {
        fprintf(stderr, "\tFlags: ECE\n");

    } else if(tcphdr->flags & TCP_CWR) {
        fprintf(stderr, "\tFlags: CWR\n");

    } else {
        fprintf(stderr, "\tFlags: NOT FOUND\n");
    }

    fprintf(stderr, "\tWindow length: %d\n", ntohs(tcphdr->window));
    fprintf(stderr, "\tChecksum: %d\n", ntohs(tcphdr->checksum));
    fprintf(stderr, "\tUrgent: %d\n", ntohs(tcphdr->urgent));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t* buf) {
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(buf);
    fprintf(stderr, "ICMP header:\n");
    fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
    fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
    /* Keep checksum in NBO */
    fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t* buf) {
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(buf);
    fprintf(stderr, "ARP header\n");
    fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
    fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
    fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
    fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
    fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

    fprintf(stderr, "\tsender hardware address: ");
    print_addr_eth(arp_hdr->ar_sha);
    fprintf(stderr, "\tsender ip address: ");
    print_addr_ip_int(ntohl(arp_hdr->ar_sip));

    fprintf(stderr, "\ttarget hardware address: ");
    print_addr_eth(arp_hdr->ar_tha);
    fprintf(stderr, "\ttarget ip address: ");
    print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t* buf, uint32_t length) {

    /* Ethernet */
    int minlength = sizeof(sr_ethernet_hdr_t);

    if(length < minlength) {
        fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
        return;
    }

    uint16_t ethtype = ethertype(buf);
    print_hdr_eth(buf);

    if(ethtype == ethertype_ip) {  /* IP */
        minlength += sizeof(sr_ip_hdr_t);

        if(length < minlength) {
            fprintf(stderr, "Failed to print IP header, insufficient length\n");
            return;
        }

        print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
        uint8_t ip_proto = ip_protocol(unwrap_ip_header(buf));

        if(ip_proto == ip_protocol_icmp) {  /* ICMP */
            minlength += sizeof(sr_icmp_hdr_t);

            if(length < minlength) {
                fprintf(stderr, "Failed to print ICMP header, insufficient length\n");

            } else {
                print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            }

        } else if(ip_proto == ip_protocol_tcp) { /* TCP */
            minlength += sizeof(sr_tcp_hdr_t);

            if(length < minlength) {
                fprintf(stderr, "Failed to print TCP header, insufficient length\n");

            } else {
                print_hdr_tcp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            }
        }

    } else if(ethtype == ethertype_arp) {  /* ARP */
        minlength += sizeof(sr_arp_hdr_t);

        if(length < minlength) {
            fprintf(stderr, "Failed to print ARP header, insufficient length\n");

        } else {
            print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
        }

    } else {
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }
}

