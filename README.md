Anteater Packet Analyzer Alpha Version 1.1 Formal README

I. Functionality

The Anteater is a packet analyzer (better known by the more loaded term 'packet sniffer') that is capable of monitoring and displaying network traffic moving to and from the host computer. It does this by capturing packets (more technically termed 'frames' here) at OSI layer 2, better known as the Link Layer, which allows it to gain an incredible amount of information about each and every bit of information that is transmitted to and from your host system. This makes the Anteater great for debugging, learning about computer networking, and LARPing as a cool black hoodie hacker. 

II. Usage

The Anteater currently only supports Linux systems. 
To run it, simply execute the binary with your choice of options (displayed below).
The binary MUST be executed with root privileges, due to the sensitive nature of raw socket reading (packet sniffing).
Running the program without any options prints only the start and end messages for each packet.

III. Options

-all -> enable all following options

-ether -> print ethernet header information

-ip -> print IPV4 header information, if present

-ipv6 -> print IPV6 header information, if present

-icmp -> print ICMP header information, if present

-icmpv6 -> print ICMPV6 header information, if present

-tcp -> print TCP header information, if present

-udp -> print UDP header information, if present

-p -> print packet payload

-file -> redirect output to a given file (name must be provided after option like so: ./anteater -file <filename>

IV. Example

./anteater -ether -ip -tcp

The above calls the program and commands it to print all collected Ethernet headers, IPV4 headers, and TCP headers.
