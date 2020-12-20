/**
 * soubor: myriprequest.cpp
 * autor: Vojtech Curda, 3BIT
 *
 */
#include <getopt.h>
#include <cstdlib>
#include <string>
#include <iostream>
#include <cstring>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "rip_defs.h"

using namespace std;

typedef struct {            // Argument structure
    char *interface;
    struct in6_addr *ip;
    int mask;
    int route_tag;
    int metric;
} args_s;

/**
 * Prints usasge
 */
void print_help() {
    cout << "Usage:" << endl <<
         "./myripresponse -i <interface> -r <IPv6>/[0-128] {-m [0-16]} {-t [0-65535]} {-h}\n" << endl <<
         " -i\t\tInterface" << endl <<
         " -r\t\tIPv6 address/mask" << endl <<
         " -m\t\tMetric value" << endl <<
         " -t\t\tRoute Tag value" << endl <<
         " -h\t\tHelp" << endl;
}

/**
 *  Parsing arguments from command line
 * @param argc
 * @param argv
 * @return      Argument structure | nullptr in case of invalid arguments
 */
args_s *get_args(int argc, char **argv) {
    int c;

    args_s *args = (args_s *) malloc(sizeof(args_s));
    args->interface = nullptr;
    args->ip = nullptr;
    args->metric = 1;
    args->route_tag = 0;

    while ((c = getopt(argc, argv, "i:r:m:t:h")) != -1) {
        switch (c) {
            case 'i':                                                       // Interface
                if (optarg) {
                    size_t len = strlen(optarg);
                    args->interface = (char *) malloc(len + 1);
                    if (args->interface == nullptr) {
                        cerr << "ERROR: malloc() failed" << endl;
                        exit(EXIT_FAILURE);
                    }
                    memset(args->interface, 0, len + 1);
                    strcpy(args->interface, optarg);

                } else {
                    cerr << "ERROR: no interface given" << endl;
                    return nullptr;
                }
                break;
            case 'r':                                                       // Address
                if (optarg) {
                    string value = optarg;
                    if (value.find('/') != string::npos) {

                        /* IP */
                        args->ip = (struct in6_addr *) malloc(sizeof(struct in6_addr));
                        if (args->ip == nullptr) {
                            cerr << "ERROR: malloc() failed" << endl;
                            exit(EXIT_FAILURE);
                        }
                        string ip = value.substr(0, value.find('/'));
                        int s = inet_pton(AF_INET6, ip.c_str(), args->ip);
                        if (s <= 0) {
                            if (s == 0)
                                cerr << "ERROR: IP Address not in presentation format" << endl;
                            else
                                perror("inet_pton");
                            return nullptr;
                        }
                        /* MASK */
                        string mask = value.substr(value.find('/') + 1, value.length());
                        try {
                            args->mask = stoi(mask);
                        } catch (exception &e) {
                            cerr << "ERROR: Incorrect mask" << endl;
                            return nullptr;
                        }
                        if (args->mask > 128 || args->mask < 0) {
                            cerr << "ERROR: Incorrect mask size" << endl;
                            return nullptr;
                        }

                    } else {
                        cerr << "ERROR: no mask given" << endl;
                        return nullptr;
                    }
                } else {
                    cerr << "ERROR: no address given" << endl;
                    return nullptr;
                }
                break;
            case 'm':                                                   // Metric
                if (optarg) {
                    try {
                        args->metric = stoi(optarg);
                    } catch (exception &e) {
                        cerr << "ERROR: Incorrect metric" << endl;
                        return nullptr;
                    }

                    if (args->metric > 16 || args->metric < 0) {
                        cerr << "ERROR: Incorrect metric value" << endl;
                        return nullptr;
                    }
                } else {
                    cerr << "ERROR: no metric value given" << endl;
                    return nullptr;
                }
                break;
            case 't':                                                   // Route tag
                if (optarg) {
                    try {
                        args->route_tag = stoi(optarg);
                    } catch (exception &e) {
                        cerr << "ERROR: Incorrect router tag" << endl;
                        return nullptr;
                    }

                    if (args->route_tag > 65535 || args->route_tag < 0) {
                        cerr << "ERROR: Incorrect router tag value" << endl;
                        return nullptr;
                    }

                } else {
                    cerr << "ERROR: no router tag value given" << endl;
                    return nullptr;
                }
                break;
            case 'h':                                                   // Help
                return nullptr;

            default:
                cerr << "ERROR: incorrect parameter" << endl;
                return nullptr;
        }
    }
    if (args->interface == nullptr) {
        cerr << "ERROR: required parameter missing: \"-i <interface>\"" << endl;
        return nullptr;
    }
    if (args->ip == nullptr) {
        cerr << "ERROR: required parameter missing: \"-r <IPv6>/[0-128]\"" << endl;
        return nullptr;
    }
    return args;
}

/**
 * Debug function
 * @param args
 */
void print_args(args_s *args) {
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, args->ip, ip, INET6_ADDRSTRLEN);
    cout << "interface: " << args->interface << endl;
    cout << "ipv6: " << ip << "/" << args->mask << endl;
    cout << "route tag: " << args->route_tag << endl;
    cout << "metric: " << args->metric << endl;
}

/**
 * Set entry members based on args
 * @param args  Arguments
 * @return      Entry
 */
ripng_entry fill_in_entry(args_s *args) {
    ripng_entry entry = {*args->ip, htons((uint16_t) args->route_tag), (uint8_t) args->mask, (uint8_t) args->metric};
    return entry;
}

/**
 * Free argument structure from memory
 * @param args  argument structure
 */
void free_args(args_s *args) {
    free(args->ip);
    free(args->interface);
    free(args);
}

int main(int argc, char **argv) {
    args_s *args = get_args(argc, argv);                                // Getting args
    if (args == nullptr) {
        print_help();
        return EXIT_FAILURE;
    }

    //print_args(args);

    const size_t PACKET_SIZE = RIP_HEADER_LENGTH + RIP_ENTRY_LENGTH;    // Size of RIP part of packet
    u_char *packet = (u_char *) malloc(PACKET_SIZE);                    // Pointer to a block of memory that represents a packet
    rip_header header = {RIP_REQUEST, 1, 0};                            // Setting RIP header
    ripng_entry entry = fill_in_entry(args);                            // Filling in entry

    memcpy(packet, &header, RIP_HEADER_LENGTH);                         // Inserting header into packet
    memcpy(packet + RIP_HEADER_LENGTH, &entry, RIP_ENTRY_LENGTH);       // Inserting entry into packet

    /* Setting source and destination addresses
     * destination = multicast address FF02::9 */
    sockaddr_in6 source_address;
    sockaddr_in6 destination_address;
    memset(&source_address, 0, sizeof(sockaddr_in6));
    memset(&destination_address, 0, sizeof(sockaddr_in6));
    source_address.sin6_family = AF_INET6;
    source_address.sin6_addr = in6addr_any;
    source_address.sin6_port = htons(RIPNG_PORT);
    destination_address.sin6_family = AF_INET6;
    destination_address.sin6_port = htons(RIPNG_PORT);
    inet_pton(AF_INET6, RIPNG_MULTICAST_ADDRESS, &destination_address.sin6_addr);

    /* Creating socket */
    int sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd < 0) {
        cerr << "ERROR: cannot open socket" << endl;
        return EXIT_FAILURE;
    }

    /* Setting max. multicast hops to 255*/
    int hops = 255;
    setsockopt(sock_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));

    /* Interface binding */
    setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, args->interface, strlen(args->interface));
    if (bind(sock_fd, (struct sockaddr *) &source_address, sizeof(source_address)) < 0) {
        cerr << "ERROR: cannot bind socket" << endl;
        cerr << "Try again with sudo" << endl;
        return EXIT_FAILURE;
    }

    /* Sending packet */
    if (sendto(sock_fd, packet, PACKET_SIZE, 0, (struct sockaddr *) &destination_address, sizeof(sockaddr_in6)) < 0){
        cerr << "ERROR: cannot send packet" << endl;
        return EXIT_FAILURE;
    } else{
        cout << "Request packet sent" << endl;
    }

    free_args(args);

    return 0;
}
