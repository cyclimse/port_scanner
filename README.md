# Computer Networks - Project 2 Ports

## Description

In order to solve each puzzle, we made a different program that would execute the task. Unfortunately, we couldn't quite figure out how to merge everything into two programs as one of the solvers is unreliable (the checksum solver). 

## Building

```bash
make
```

## How were those programs used to solve the puzzles

We first started by scanning the different ports of skel.ru.is to find the open ports using the scanner program:

```bash
./scanner 130.208.243.61 4000 4100
```

Once this was done, we sent our group number "$group_11$"  with the `mystery` program to the port which was asking for it:

```bash
./mystery 130.208.243.61 4004 '$group_11$'
```

Mystery is a very simple program which just send a UDP packet with a user inputed message.

This port then asks for a message with a specific checksum. To send such a message, we made the program `raw`. Unfortunately, it does not work for most checksums as it uses only the char 0x1 to compose its messages and goes on to brutforce the checksum. So a lot of the time the packages it composes are too large to be sent.
We tried various approaches, like computing the size of the payload by subtracting from the target checksum the checksum of a blank packet with no payload.
Unfortunately, at the end, we weren't able to have a working solution that didn't make use of brutforce.

```bash
sudo ./raw 130.208.243.61 4045 target_checksum
```

After a few tries, we were able to find the passphrase: "Ennyn Durin Aran Moria. Pedo Mellon a Minno. Im Narvi hain echant. Celebrimbor o Eregion teithant i thiw hin.".

For the evil bit, we tweaked the way we create UDP datagrams on a raw socket to set the reserved bit of the frag_off field of the IP header.

```bash
sudo ./evil 130.208.243.61 4002 '$group_11$'
```

We were then able to find all of the secret ports and proceed to contact the oracle:

```bash
./mystery 130.208.243.61 4045 '4004,4005'
```

And then knocked on the ports with the passphrase using a small utility program:

```bash
./knock 130.208.243.61 "Ennyn Durin Aran Moria. Pedo Mellon a Minno. Im Narvi hain echant. Celebrimbor o Eregion teithant i thiw hin."
```

To send the final ICMP echo request with the message "$group_11$", we used the ping utility command:

```bash
ping 130.208.243.61 -p 2467726f75705f313124 -s 10
```

## Authors

Andy Méry
Luca FLuri
