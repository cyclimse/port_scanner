#include <array>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h> // close(...)

int main(int argc, char *const argv[]) {

  if (argc < 4) {
    std::cout << "Usage: ./mystery <ip> <port> <message>";
    exit(0);
  }

  char const *ip{argv[1]};
  int const port{std::atoi(argv[2])};
  std::string const message{(char const *) argv[3]};

  int sfd;
  if ((sfd = socket(AF_INET, (SOCK_DGRAM), 0)) == -1) {
    throw std::runtime_error{strerror(errno)};
  }

  constexpr std::size_t buffer_size{256};

  struct sockaddr_in addr;
  int slen{sizeof(addr)};

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);
  addr.sin_port = htons(port);

  if (sendto(sfd, message.c_str(), message.size(), 0,
             (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
    throw std::runtime_error{strerror(errno)};
  }

  sockaddr_in src;
  socklen_t src_len{sizeof(src)};

  std::array<char, buffer_size> buffer;
  if (recvfrom(sfd, &buffer, buffer_size, 0, (struct sockaddr *)&src,
               &src_len) == -1) {
    throw std::runtime_error{strerror(errno)};
  };

  if (ntohs(src.sin_port) != port) {
    throw std::runtime_error{"wtf"};
  }

  close(sfd);

  std::cout << "Sent:\n" << message << std::endl;
  std::cout << "Message:\n" << buffer.data() << std::endl;
}