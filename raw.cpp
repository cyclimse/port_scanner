#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <netinet/ip.h>  // ip header
#include <netinet/udp.h> // udp header --> udphdr

#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // close(...)

#include <iomanip>
#include <sstream>

std::string get_byte_hexdump(void *buffer, int buflen) {
  /**
      Author Benedikt H. Thordarson.
      Given buffer b, and length of b in bytes bufen,
      print buffer in wireshark format.
      output works for wireshark imports.
  **/

  // create byte buffer.
  unsigned char *byte_buffer = (unsigned char *)buffer;
  std::string hexdump = "";
  for (int i = 0; i < buflen; i += 16) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    // show addr offset
    ss << std::setw(8) << std::hex << i;
    int j = 0;

    for (j = 0; j < 16; j++) {
      // break before we go out of bounds
      if (i + j == buflen) {
        break;
      }
      // if we are at the 8B place, inject extra space
      if (j % 8 == 0 && j != 0) {
        ss << " ";
      }
      // inject space
      ss << " " << std::hex << std::setw(2) << (unsigned int)byte_buffer[i + j];
    }
    // pad to length before we add our char printouts.
    while (j < 16) {
      ss << "   ";
      j += 1;
    }
    // Add the char print.
    ss << "\t| ";
    for (j = 0; j < 16; j++) {
      // do not go out of bounds.
      if (i + j == buflen) {
        break;
      }
      if (j % 8 == 0 && j != 0) {
        ss << " ";
      }
      // if the character is not printable or is a newline, print a star.
      if (byte_buffer[i + j] == (unsigned char)'\n' ||
          !std::isprint(byte_buffer[i + j])) {
        ss << "*";
      } else {
        ss << byte_buffer[i + j];
      }
    }
    // add newline and append to dump.
    ss << "\n";
    hexdump += ss.str();
  }
  return hexdump;
}

// Reference material: https://en.wikipedia.org/wiki/IPv4_header_checksum
template <size_t N>
static inline std::uint16_t
compute_checksum(std::array<std::uint16_t, N> const &bin_vec) {
  std::uint32_t checksum = 0;

  for (const std::uint16_t &bin_word : bin_vec) {
    checksum += bin_word;
  }
  std::cout << std::hex << checksum << std::endl;
  while (checksum >> 16) {
    checksum = (checksum & 0xFFFF)+(checksum >> 16);
  }
  return ~checksum;
}

static inline std::uint16_t compute_udp_checksum(struct udphdr const &udp_header, struct iphdr const& ip_header) {

  struct pseudo_header {
    std::uint32_t source;
    std::uint32_t dest;
    std::uint16_t protocol;
    std::uint16_t len;
  };

  struct pseudo_header pseudo;
  pseudo.source = inet_addr("130.208.24.6");
  pseudo.dest = ip_header.daddr;
  pseudo.protocol = ntohs(ip_header.protocol);
  pseudo.len = udp_header.len;

  std::cout << std::hex << pseudo.source << std::endl;
  std::cout << std::hex << pseudo.dest << std::endl;
  std::cout << std::hex << pseudo.protocol << std::endl;
  std::cout << std::hex << pseudo.len << std::endl;

  std::array<std::uint16_t, sizeof(pseudo_header) / 2> pseudo_header_bin;
  memcpy(&pseudo_header_bin, &pseudo, sizeof(pseudo_header));

  //std::cout << get_byte_hexdump(&pseudo_header_bin, sizeof(pseudo_header)) << std::endl;
  for (auto &number : pseudo_header_bin) {
    std::cout << std::hex << number << std::endl;
  }


  return compute_checksum(pseudo_header_bin);
}

int main(int argc, char *const argv[]) {

  constexpr char payload[] = "lol";

  if (argc < 3) {
    std::cout << "Usage: ./raw <ip> <port>";
    exit(0);
  }

  char const *ip{argv[1]};
  int const port{std::atoi(argv[2])};

  int sfd;
  if ((sfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
    char const *error = strerror(errno);
    char message[] = "Socket could not be created: ";
    throw std::runtime_error{strcat(message, error)};
  }

  const int hdr_included = 1;
  if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &hdr_included,
                 sizeof(hdr_included)) < 0) {
    char const *error = strerror(errno);
    char message[] = "Could not set IP_HDRINCL option: ";
    throw std::runtime_error{strcat(message, error)};
  }

  struct sockaddr_in my_addr;
  socklen_t my_addrlen = sizeof(my_addr);
  if (getsockname(sfd, (struct sockaddr *)&my_addr, &my_addrlen) == -1) {
    char const *error = strerror(errno);
    char message[] = "Could not get port from socket: ";
    throw std::runtime_error{strcat(message, error)};
  }

  // We set up the receiver.
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);
  addr.sin_port = htons(port);

  // We start by filling the UDP header.
  struct udphdr udp_header;
  udp_header.uh_sport = my_addr.sin_port;
  udp_header.uh_dport = addr.sin_port;

  constexpr std::uint16_t length_udp{sizeof(struct udphdr) + sizeof(payload)};
  udp_header.len = htons(length_udp);
  udp_header.check = 0;

  // Reference material: https://en.wikipedia.org/wiki/IPv4#Header
  struct iphdr ip_header;
  // We are using IPv4.
  ip_header.version = 4;
  // Internet Header Length (IHL)
  ip_header.ihl = 5;
  // Type Of Service (TOS)
  // Reference material: https://en.wikipedia.org/wiki/Type_of_service
  ip_header.tos = 0; // Best effort
  constexpr std::uint32_t length_total{sizeof(struct iphdr) + length_udp};
  ip_header.tot_len = length_total;
  // Identification
  ip_header.id = 0;
  ip_header.frag_off = 0;
  // We do this with postcards too.
  ip_header.saddr = my_addr.sin_addr.s_addr;
  ip_header.daddr = addr.sin_addr.s_addr;
  ip_header.ttl = 0xFF;
  // Reference material:
  // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
  ip_header.protocol = 0x11; // UDP
  ip_header.check = 0;

  // Let's compute the checksum.
  std::array<std::uint16_t, sizeof(ip_header) / 2> ip_header_bin;
  memcpy(&ip_header_bin, &ip_header, sizeof(ip_header));

  ip_header.check = compute_checksum(ip_header_bin);
  udp_header.check = compute_udp_checksum(udp_header, ip_header);

  std::array<char, sizeof(ip_header)+sizeof(udp_header)+sizeof(payload)> packet{};
  memcpy(packet.data(), &ip_header, sizeof(ip_header));
  memcpy(packet.data() + sizeof(ip_header), &udp_header, sizeof(udp_header));
  memcpy(packet.data() + sizeof(ip_header)+sizeof(udp_header), &payload, sizeof(payload));

  if (sendto(sfd, packet.data(), ip_header.tot_len, 0, (struct sockaddr *)&addr,
             sizeof(addr)) == -1) {
    char const *error = strerror(errno);
    char message[] = "sendto : ";
    throw std::runtime_error{strcat(message, error)};
  }

  close(sfd);
}