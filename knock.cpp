#include <array>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string.h>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h> // close(...)

int main(int argc, char *const argv[]) {

  if (argc < 3) {
    std::cout << "Usage: ./knock <ip> <message>";
    exit(0);
  }

  char const *ip{argv[1]};
  std::string const message{(char const *)argv[2]};
  static const std::vector<int> ports{4005, 4004, 4004, 4004, 4005};

  int sfd;
  if ((sfd = socket(AF_INET, (SOCK_DGRAM), 0)) == -1) {
    throw std::runtime_error{strerror(errno)};
  }

  constexpr std::size_t buffer_size{256};

  struct sockaddr_in addr;
  int slen{sizeof(addr)};

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);

  for (auto const &port : ports) {

    addr.sin_port = htons(port);

    if (sendto(sfd, message.c_str(), message.size(), 0,
               (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
      throw std::runtime_error{strerror(errno)};
    }
  }

  close(sfd);

}