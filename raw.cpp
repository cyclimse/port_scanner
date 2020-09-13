#include <bitset>
#include <cstddef>
#include <cstdint>
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

// Reference material: https://en.wikipedia.org/wiki/IPv4_header_checksum
// This is probably a terrible implementation because I'm essentially writing a
// function that is implemented at the hardware level.
// After checking with compiler explorer, it is indeed terrible (less so with
// -O3, at least it will then use single bit values and recognizes the
// std::bitset as a bitstring).
template <size_t N>
static inline std::uint16_t compute_checksum(std::bitset<N> const &bs) {
  std::bitset<16> checksum{0};

  // For every 2 bytes from the bitset
  for (auto i = 0; i < N; i += 16) {
    bool carry_out{0};
    bool aux;
    for (auto j = 0; j < 16; j++) {
      // This is a full-adder
      aux = carry_out ^ checksum[j] ^ bs[i + j];
      carry_out = (checksum[j] && bs[i + j]) ||
                  (checksum[j] ^ bs[i + j] && (carry_out));
      checksum[j] = aux;
    }
    auto k = 0;
    while (k < 16 && carry_out) {
      aux = carry_out || checksum[k];
      carry_out = carry_out && checksum[k];
      checksum[k] = aux;
    }
  }

  return static_cast<std::uint16_t>(checksum.flip().to_ulong());
}

int main(int argc, char *const argv[]) {

  constexpr unsigned short my_port{6666};
  constexpr char payload[] = "lol";
  constexpr char my_ip[] = "127.0.0.1";

  if (argc < 3) {
    std::cout << "Usage: ./raw <ip> <port>";
    exit(0);
  }

  char const *ip{argv[1]};
  int const port{std::atoi(argv[2])};

  int sfd;
  if ((sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
    char const *error = strerror(errno);
    char message[] = "Socket could not be created: ";
    throw std::runtime_error{strcat(message, error)};
  }

  // This time we will bind the client to a set local port. This is because when
  // crafting the packet, we need to indicate the source port.
  struct sockaddr_in my_addr;

  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  my_addr.sin_port = htons(my_port);

  if (bind(sfd, (const struct sockaddr *)&my_addr, sizeof(my_addr)) == -1) {
    char const *error = strerror(errno);
    char message[] = "Socket could not be bound: ";
    throw std::runtime_error{strcat(message, error)};
  }

  // We set up the receiver.
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);
  addr.sin_port = htons(port);

  // We start by filling the UDP header.
  struct udphdr udp_header;
  udp_header.source = htons(my_port);
  udp_header.dest = htons(port);

  constexpr std::uint16_t length_udp{sizeof(struct udphdr) + sizeof(payload)};
  udp_header.len = htons(length_udp);

  // Reference material: https://en.wikipedia.org/wiki/IPv4#Header
  struct iphdr ip_header;
  // We are using IPv4.
  ip_header.version = 4;
  // Internet Header Length (IHL)
  ip_header.ihl = 5; // TODO: change this so its not hard-coded and based
                     // on what we've filled up the struct with.
  // Type Of Service (TOS)
  // Reference material: https://en.wikipedia.org/wiki/Type_of_service
  ip_header.tos = 0; // Best effort
  constexpr std::uint32_t length_total{sizeof(struct iphdr) + length_udp};
  ip_header.tot_len = length_total;
  // Identification
  ip_header.id = 12345;
  ip_header.frag_off = 0;
  // We do this with postcards too.
  ip_header.saddr = inet_addr(my_ip);
  ip_header.daddr = addr.sin_addr.s_addr;
  ip_header.ttl = 0xFF;
  // Reference material:
  // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
  ip_header.protocol = 0x11; // UDP
  ip_header.check = 0;

  // Let's compute the checksum.
  std::bitset<8 * sizeof(ip_header)> ip_header_bin;
  memcpy(&ip_header_bin, &ip_header, sizeof ip_header);

  ip_header.check = compute_checksum(ip_header_bin);

  close(sfd);
}