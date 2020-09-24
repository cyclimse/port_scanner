#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>

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

struct pseudohdr {
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t udp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes) {
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *)&oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (short)~sum;

  return (answer);
}

// compute_checksums compute the ip checksum and also the udp checksum by
// filling out a udp pseudo_header
template <size_t N>
static inline void compute_checksums(std::array<char, N> &datagram,
                                     iphdr *ip_header, udphdr *udp_header,
                                     std::string const &payload) {
  ip_header->check =
      csum((unsigned short *)datagram.data(), ip_header->tot_len);

  std::vector<char> checksum_buffer(sizeof(struct pseudohdr) +
                                    sizeof(struct udphdr) + payload.size());
  struct pseudohdr *pseudo_header = (struct pseudohdr *)checksum_buffer.data();
  pseudo_header->source_address = ip_header->saddr;
  pseudo_header->dest_address = ip_header->daddr;
  pseudo_header->placeholder = 0;
  pseudo_header->protocol = ip_header->protocol;
  pseudo_header->udp_length = udp_header->uh_ulen;

  std::memcpy(checksum_buffer.data() + sizeof(struct pseudohdr), udp_header,
              sizeof(struct udphdr));
  std::memcpy(checksum_buffer.data() + sizeof(struct pseudohdr) +
                  sizeof(struct udphdr),
              payload.c_str(), payload.size());

  // std::cout << get_byte_hexdump(checksum_buffer.data(),
  // checksum_buffer.size())
  //           << std::endl;

  udp_header->uh_sum =
      csum((unsigned short *)checksum_buffer.data(), checksum_buffer.size());
}

// fill_headers_from_payload fills up the ip and udp headers with the
// appropriate information.
static inline void fill_headers_from_payload(
    iphdr *ip_header, udphdr *udp_header, std::string const &payload,
    const char *my_ip, struct sockaddr_in &my_addr, struct sockaddr_in &addr) {
  // We are using IPv4.
  ip_header->version = 4;
  // Internet Header Length (IHL)
  ip_header->ihl = 5;
  // Type Of Service (TOS)
  // Reference material: https://en.wikipedia.org/wiki/Type_of_service
  ip_header->tos = 0; // Best effort
  ip_header->tot_len =
      sizeof(struct iphdr) + sizeof(struct udphdr) + payload.size();
  // Identification
  ip_header->id = 0;
  ip_header->frag_off |= ntohs(IP_RF);
  // We do this with postcards too.
  ip_header->saddr = inet_addr(my_ip);
  ip_header->daddr = addr.sin_addr.s_addr;
  ip_header->ttl = 64;
  // Reference material:
  // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
  ip_header->protocol = IPPROTO_UDP; // UDP
  ip_header->check = 0;

  udp_header->uh_sport = my_addr.sin_port;
  udp_header->uh_dport = addr.sin_port;
  udp_header->uh_ulen = htons(sizeof(struct udphdr) + payload.size());
  udp_header->uh_sum = 0;
}

int main(int argc, char *const argv[]) {

  // This needs to be set manually.
  constexpr char my_ip[] = "130.208.24.6";

  if (argc < 4) {
    std::cout << "Usage: ./raw <ip> <port> <message>";
    exit(0);
  }

  char const *ip{argv[1]};
  int const port{std::atoi(argv[2])};
  std::string const payload{(char const *)argv[3]};

  int sfd;
  if ((sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
    throw std::runtime_error{strerror(errno)};
  }

  const int hdr_included = 1;
  if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &hdr_included,
                 sizeof(hdr_included)) < 0) {
    throw std::runtime_error{strerror(errno)};
  }

  struct sockaddr_in my_addr;
  socklen_t my_addrlen = sizeof(my_addr);
  if (getsockname(sfd, (struct sockaddr *)&my_addr, &my_addrlen) == -1) {
    throw std::runtime_error{strerror(errno)};
  }

  // We set up the receiver.
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);
  addr.sin_port = htons(port);

  ///////////////////////////////////////////////////////////////////////////
  // We start filing out the datagram
  ///////////////////////////////////////////////////////////////////////////

  std::array<char, 10506> datagram{};
  struct iphdr *ip_header = (struct iphdr *)datagram.data();
  struct udphdr *udp_header =
      (struct udphdr *)(datagram.data() + sizeof(struct iphdr));
  datagram.fill(0);
  std::memcpy(datagram.data() + sizeof(struct iphdr) + sizeof(struct udphdr),
              payload.c_str(), payload.size());

  fill_headers_from_payload(ip_header, udp_header, payload, my_ip, my_addr,
                            addr);
  compute_checksums(datagram, ip_header, udp_header, payload);

  if (sendto(sfd, datagram.data(), ip_header->tot_len, 0,
             (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    throw std::runtime_error{strerror(errno)};
  }

  close(sfd);
}