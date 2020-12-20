/**
 * soubor: myripsniffer.cpp
 * autor: Vojtech Curda, 3BIT
 *
 */
#include <iostream>
#include <cstring>
#include <iomanip>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <csignal>

#include "rip_defs.h"

using namespace std;

pcap_t *handler;        // file/device handler


/** Parse arguments from cmd
 *  Returns 1 in case of correct argument structure, 0 otherwise
 */
int get_arg(int argc, char **argv, string *interface) {
    if (argc != 3)
        return 0;
    if (strcmp(argv[1], "-i") != 0)
        return 0;
    *interface = argv[2];
    return 1;
}

/**
 *  Prints RIP packet info
 * @param RIPng         is it RIPng?
 * @param src_ip        source ip address
 * @param dst_ip        destination ip address
 * @param udp_header    UDP header
 * @param rip_header    RIP header
 */
void print_packet_info(bool RIPng, char *src_ip, char *dst_ip, udphdr *udp_header, rip_header *rip_header, size_t packet_size) {
    string version;
    string command;

    /* Parse version */
    if (RIPng) {
        if (rip_header->version == 1)
            version = "RIPng";
        else
            version = "Unknown RIPng version";

    } else {
        switch (rip_header->version) {
            case 1:
                version = "RIPv1";
                break;
            case 2:
                version = "RIPv2";
                break;
            default:
                version = "Unknown RIP version";
                break;
        }

    }

    /* Parse command */
    switch (rip_header->command) {
        case 1:
            command = "Request";
            break;
        case 2:
            command = "Response";
            break;
        default:
            command = "Unknown Command";
    }

    /* Getting local time */
    time_t t = time(nullptr);
    struct tm *local_time = localtime(&t);
    char tstring[9];
    strftime(tstring, 9, "%T", local_time);


    size_t max_ip_len = strlen(src_ip) > strlen(dst_ip) ? strlen(src_ip) : strlen(dst_ip);


    /* Print data*/
    cout << "[" << version << "]     " << "Src IP: " << setw(max_ip_len+3) << left << src_ip
         << "Src Port: " << setw(8) << left << ntohs(udp_header->source)
         << "Command: " << setw(8) << left << command << endl;

    cout << "(" << tstring << ")  " << "Dst IP: " << setw(max_ip_len+3) << left << dst_ip
         << "Dst Port: " << setw(8) << left << ntohs(udp_header->dest)
         <<  "Length:  " << setw(8) << left << packet_size << endl;


    for (uint32_t i = 0; i < max_ip_len + 60; ++i) {
        cout << "─";
    }
    cout << endl;

}

/**
 *  Prints entry header
 * @param entry     Type of entry
 */
void print_entry_header(entry_type entry) {
    switch (entry) {
        case IP_ENTRY:
            cout << "┌───────────────── IP Address Entry ─────────────────┐" << endl;
            break;

        case NEXT_HOP_ENTRY:
            cout << "┌────────────────── Next-hop Entry ──────────────────┐" << endl;
            break;

        case ROUTE_TABLE_ENTRY:
            cout << "┌───────────────── Route Table Entry ────────────────┐" << endl;
            break;

        case SIMPLE_AUTH_ENTRY:
            cout << "┌────────────── Authentification Entry ──────────────┐" << endl;
            break;

        case MD5_AUTH_ENTRY:
            cout << "┌──────────── MD5 Authentification Entry ────────────┐" << endl;
            break;

        case AUTH_DATA_TRAILER:
            cout << "┌─────────── Authentification Data Trailer ──────────┐" << endl;
            break;
    }
}

/**
 *  Prints one attribute of an entry
 * @param name
 * @param value
 */
void print_entry_member(string name, string value) {
    cout << "│ " << setw(19) << left << name.append(1, ':') << setw(32) << left << value << "│" << endl;

}

/**
 * Parses and prints entries of a RIP packet
 * @param RIPng         is it RIPng?
 * @param rip_header    RIP header
 * @param rip_length    Size of RIP part of packet
 */
void print_rip_entries(bool RIPng, rip_header *rip_header, size_t rip_length) {
    for (size_t entry_parsed = 0; entry_parsed != rip_length - sizeof(struct rip_header); entry_parsed += 20) {

        if (RIPng) {                    // RIPng

            /* Getting next entry */
            ripng_entry *entry = (ripng_entry *) ((u_char *) rip_header + RIP_HEADER_LENGTH + entry_parsed);

            /* Getting IPv6 address in string */
            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &entry->ip_prefix, ipv6, INET6_ADDRSTRLEN);

            if (entry->metric == 0xFF) {                // Next-hop entry
                print_entry_header(NEXT_HOP_ENTRY);
                print_entry_member("Next-Hop", ipv6);

            } else {                                    // IPv6 prefix entry
                print_entry_header(ROUTE_TABLE_ENTRY);
                print_entry_member("IPv6 Prefix", ipv6);
                print_entry_member("Route tag", to_string(ntohs(entry->route_tag)));
                print_entry_member("Prefix Length", to_string((int) entry->prefix_length));
                print_entry_member("Metric", to_string((int) entry->metric));
            }
        } else {                        // RIPv1/2

            /* Getting next entry */
            rip_entry *entry = (rip_entry *) ((u_char *) rip_header + RIP_HEADER_LENGTH + entry_parsed);

            if (entry->afi == 0xFFFF) {      // Authentification entry

                if (ntohs(entry->route_tag) == 1) {         // Authentification data trailer
                    char auth_data[33] = {0};

                    /* Conversion of data into hexadecimal form */
                    for (int i = 0; i < 16; ++i) {
                        snprintf(auth_data + (i * 2), 3, "%02x", entry->data.md5_data_trailer.data[i]);
                    }

                    print_entry_header(AUTH_DATA_TRAILER);
                    print_entry_member("Auth data", auth_data);


                } else if (ntohs(entry->route_tag) == 2) {   // Simple password
                    char password[17] = {0};
                    memcpy(password, entry->data.auth_pass.password, 16);

                    print_entry_header(SIMPLE_AUTH_ENTRY);
                    print_entry_member("Auth type", "Simple Password");
                    print_entry_member("Password", password);

                } else if (ntohs(entry->route_tag) == 3) {   // MD5 auth
                    print_entry_header(MD5_AUTH_ENTRY);
                    print_entry_member("Auth type", "MD5");
                    print_entry_member("MD5 digest offset", to_string(ntohs(entry->data.md5_auth.digest_offset)));
                    print_entry_member("Key ID", to_string(entry->data.md5_auth.key_id));
                    print_entry_member("Auth Data Len", to_string(entry->data.md5_auth.auth_data_len));
                    print_entry_member("Seq num", to_string(ntohl(entry->data.md5_auth.seq_num)));
                }

            } else {                                         // Non-authentification entry

                if (rip_header->version == 1) {              // RIPv1
                    print_entry_header(IP_ENTRY);
                    print_entry_member("Address Family", to_string(ntohs(entry->afi)));
                    print_entry_member("IP Address", inet_ntoa(entry->data.simple_entry.ip));
                    print_entry_member("Metric", to_string(ntohl(entry->data.simple_entry.metric)));

                } else {                                    // RIPv2
                    print_entry_header(IP_ENTRY);
                    print_entry_member("Address Family", to_string(ntohs(entry->afi)));
                    print_entry_member("Route Tag", to_string(ntohs(entry->route_tag)));
                    print_entry_member("IP Address", inet_ntoa(entry->data.simple_entry.ip));
                    print_entry_member("Mask", inet_ntoa(entry->data.simple_entry.mask));
                    print_entry_member("Next-Hop", inet_ntoa(entry->data.simple_entry.next_hop));
                    print_entry_member("Metric", to_string(ntohl(entry->data.simple_entry.metric)));
                }
            }
        }

        /* Newline after last entry*/
        if ((rip_length - RIP_HEADER_LENGTH) - entry_parsed == RIP_ENTRY_LENGTH) {
            cout << "\n";
        }
    }
}

/**
 * Parsing packets, preparing RIP parts of packets for printing
 * @param packet
 */
void parse_packet(u_char *, const pcap_pkthdr *, const u_char *packet) {

    struct ether_header *ethernet_header = (struct ether_header *) packet;          // Ethernet header
    struct udphdr *udp_header;                                                      // UDP header
    struct rip_header *rip_header;                                                  // RIP header
    size_t rip_length;                                                              // Size of RIP part of packet


    switch (ntohs(ethernet_header->ether_type)) {
        case ETHERTYPE_IP: {                                                        // IPv4

            struct ip *ip_header = (struct ip *) (packet + ETH_HEADER_LENGTH);      // IP header
            const size_t IP_LEN = (ip_header->ip_hl) * 4;                           // IP header length

            udp_header = (struct udphdr *) (packet + ETH_HEADER_LENGTH + IP_LEN);
            if (ntohs(udp_header->source) != RIPNG_PORT && ntohs(udp_header->dest) != RIP_PORT) // Checking for RIPv1/2
                return;

            rip_header = (struct rip_header *) (packet + ETH_HEADER_LENGTH + IP_LEN + UDP_HEADER_LENGTH);
            rip_length = ntohs(udp_header->len) - UDP_HEADER_LENGTH;

            /* Getting source and destination IP in string */
            char source_ip[INET_ADDRSTRLEN];
            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

            /* Check for valid entry sizes */
            int rip_entries_size = (ntohs(udp_header->len) - UDP_HEADER_LENGTH) - RIP_HEADER_LENGTH;
            if (rip_entries_size % RIP_ENTRY_LENGTH)
                return;

            size_t packet_size = ETH_HEADER_LENGTH+IP_LEN+ntohs(udp_header->len);
            /* Printing packet info and separate RIP entries */
            print_packet_info(false, source_ip, dest_ip, udp_header, rip_header, packet_size);
            print_rip_entries(false, rip_header, rip_length);
        }
            break;
        case ETHERTYPE_IPV6: {                                                      // IPv6

            struct ip6_hdr *ipv6_header = (struct ip6_hdr *) (packet + ETH_HEADER_LENGTH);

            udp_header = (struct udphdr *) (packet + ETH_HEADER_LENGTH + IPV6_HEADER_LENGTH);
            if (ntohs(udp_header->source) != RIPNG_PORT && ntohs(udp_header->dest) != RIPNG_PORT)         // Checking for RIPng
                return;

            rip_header = (struct rip_header *) (packet + ETH_HEADER_LENGTH + IPV6_HEADER_LENGTH + UDP_HEADER_LENGTH);
            rip_length = ntohs(udp_header->len) - UDP_HEADER_LENGTH;

            /* Getting source and destination IP in string */
            char ipv6_src[INET6_ADDRSTRLEN] = {0};
            char ipv6_dst[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ipv6_src, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ipv6_dst, INET6_ADDRSTRLEN);

            /* Check for valid entry sizes */
            int rip_entries_size = (ntohs(udp_header->len) - UDP_HEADER_LENGTH) - RIP_HEADER_LENGTH;
            if (rip_entries_size % RIP_ENTRY_LENGTH)
                return;

            size_t packet_size = ETH_HEADER_LENGTH+IPV6_HEADER_LENGTH+ntohs(udp_header->len);
            /* Printing packet info and separate RIPng entries */
            print_packet_info(true, ipv6_src, ipv6_dst, udp_header, rip_header, packet_size);
            print_rip_entries(true, rip_header, rip_length);

        }
            break;
    }
}

/**
 *  Sets filter on probing interface
 * @param interface     Interface
 * @param handler       Device handler
 * @param filter        Filter in string
 * @return
 */
int set_filter(string interface, pcap_t *handler, string filter) {

    struct bpf_program bpf_filter;
    char errBuf[PCAP_ERRBUF_SIZE];

    uint32_t mask, src_ip;

    if (pcap_lookupnet(interface.c_str(), &src_ip, &mask, errBuf) < 0) {
        cerr << "ERROR: Failed to get network number " << interface.c_str() << endl;
        return -1;
    }

    if (pcap_compile(handler, &bpf_filter, filter.c_str(), 0, mask) < 0) {
        cerr << "ERROR: Compiling filter" << endl;
        return -1;
    }

    if (pcap_setfilter(handler, &bpf_filter) < 0) {
        cerr << "ERROR: Setting filter" << endl;
        return -1;
    }

    return 0;
}

/**
 * Sniffer termination service
 * @param signo     Signal number
 **/
void terminate(int signo)
{
    (void) signo;
    if (handler) {
        struct pcap_stat stats;
        if (pcap_stats(handler, &stats) >= 0) {
            cout << "\n────────────── Results ──────────────" << endl;
            cerr << setw(18) << left << "Packets received: " << stats.ps_recv << endl;
            cerr << setw(18) << left << "Packets dropped: " << stats.ps_drop << endl;
        }
        pcap_breakloop(handler);
        pcap_close(handler);
    }
    exit(0);
}


int main(int argc, char **argv) {
    signal(SIGINT, terminate);
    signal(SIGTERM, terminate);

    /* Getting interface name from args */
    string interface;
    if (!get_arg(argc, argv, &interface)){
        cout << "Incorrect parameters" << endl;
        cout << "Execute with following parameter structure:  ./myripsniffer -i <interface>" << endl;
        return EXIT_FAILURE;
    }

    char err_buf[PCAP_ERRBUF_SIZE];


    if (interface.find(".pcap") != string::npos) {
        handler = pcap_open_offline(interface.c_str(), err_buf);        // Open interface from file

    } else {

        /* Open live interface */
        handler = pcap_open_live(interface.c_str(), 500, 1, 500, err_buf);
        if (handler == nullptr) {
            cerr << "ERROR: Interface " << interface << " failed to open" << endl;
            cerr << "Try again with sudo" << endl;

            return EXIT_FAILURE;
        }

        /* Setting filter */
        if (set_filter(interface, handler, "portrange 520-521 and udp") < 0) {
            return EXIT_FAILURE;
        }
    }

    pcap_loop(handler, 0, parse_packet, nullptr);

    terminate(0);
}