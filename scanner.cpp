#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string.h>

#include <future>
#include <mutex>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int main(int argc, char *const argv[]) {

  if (argc < 4) {
    std::cout << "Usage: ./scanner <ip> <low port> <high port>";
  }

  char const *ip{argv[1]};
  int const low_port{std::atoi(argv[2])};
  int const high_port{std::atoi(argv[3])};

  // We rely on the non-blocking behavior to not get stuck on closed ports.
  int sfd;
  if ((sfd = socket(AF_INET, (SOCK_DGRAM), 0)) == -1) {
    char const *error = strerror(errno);
    char message[] = "Socket could not be created: ";
    throw std::runtime_error{strcat(message, error)};
  }

  struct sockaddr_in addr;
  int slen{sizeof(addr)};

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);

  // To get the results sorted by port at the end, we will put them in a map.
  constexpr std::size_t buffer_size{256};
  struct Entry {
    std::array<char, buffer_size> buffer;
    sockaddr_in src;
    socklen_t src_len = sizeof(src);
  };
  std::map<int, Entry> table;

  // Unfortunately, it's not possible to write concurrently in a map,
  // so we have to rely on mutexes.
  std::mutex mtx;

  // We will send the message:
  std::string const message{""};

  auto handlerReceive = [&]() {
    Entry new_entry;
    if (recvfrom(sfd, &new_entry.buffer, buffer_size, 0,
                 (struct sockaddr *)&new_entry.src, &new_entry.src_len) == -1) {
      char const *error = strerror(errno);
      char message[] = "recvfrom : ";
      throw std::runtime_error{strcat(message, error)};
    };

    if (new_entry.src_len > 0) {
      const int port = ntohs(new_entry.src.sin_port);
      const std::lock_guard<std::mutex> lock(mtx);
      table[port] = new_entry;
    }
  };

  for (int i{low_port}; i <= high_port; i++) {

    // We dial the current address.
    addr.sin_port = htons(i);

    if (sendto(sfd, message.c_str(), message.size(), 0,
               (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
      char const *error = strerror(errno);
      char message[] = "sendto : ";
      throw std::runtime_error{strcat(message, error)};
    }

    std::packaged_task<void()> task(handlerReceive);
    auto future = task.get_future();
    std::thread thr(std::move(task));
    if (future.wait_for(std::chrono::milliseconds(50)) !=
        std::future_status::timeout) {
      thr.join();
      future.get();
    } else {
      thr.detach();
    }
  }

  for (auto const &pair : table) {
    std::cout << "Port: " << pair.first << std::endl;
    std::cout << "Message:\n" << pair.second.buffer.data() << std::endl;
  }
}