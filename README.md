# Wireshark-Packet-Analysis
Analyzing packets with Wireshark on a VM

## Objective

Previously, you learned about packet capture and analysis. Analyzing packets can help security teams interpret and understand network communications. Network protocol analyzers such as Wireshark, which has a graphical user interface or GUI, can help you examine packet data during your investigations. Since network packet data is complex, network protocol analyzers (packet sniffers) like Wireshark are designed to help you find patterns and filter the data in order to focus on the network traffic that is most relevant to your security investigations.

Now you’ll use Wireshark to inspect packet data and apply filters to sort through packet information efficiently.

In this lab activity, you’ll use Wireshark to examine a sample packet capture file and filter the network traffic data.

## Project description

In this scenario, you’re a security analyst investigating traffic to a website.

  * You’ll analyze a network packet capture file that contains traffic data related to a user connecting to an internet site. The ability to filter network traffic using packet sniffers to gather relevant information is an essential skill as a security analyst.

You must filter the data in order to:

  * identify the source and destination IP addresses involved in this web browsing session
  * Examine the protocols that are used when the user makes the connection to the website
  * Analyze some of the data packets to identify the type of information sent and received by the systems that connect to each other when the network data is captured.

Here’s how you’ll do this: 
  * First, you’ll open the packet capture file and explore the basic Wireshark graphic user interface
  * Second, you’ll open a detailed view of a single packet and explore how to examine the various protocol and data layers inside a network packet
  * Third, you’ll apply filters to select and inspect packets based on specific criteria
  * Fourth, you’ll filter and inspect UDP DNS traffic to examine protocol data
  * Finally, you’ll apply filters to TCP packet data to search for specific payload text data.

You’re ready to use Wireshark to inspect network packet data!

## Skills Learned

**Exploring Packet Capture Files:**
  * Opened a .pcap file containing network traffic data captured from a web browsing session.
  * Identified key information displayed for each packet, including source and destination IP addresses, protocol used, and length.
  * Understood the color-coding scheme used to visually differentiate different types of traffic (e.g., blue for DNS, green for TCP/HTTP).

**Applying Filters:**
  * Used basic filters to narrow down displayed traffic based on specific criteria like source/destination IP addresses or port numbers (e.g., ip.addr == 142.250.1.139, udp.port == 53).
  * Learned how to filter for specific Ethernet MAC addresses (eth.addr == 42:01:ac:15:e0:02).

**Inspecting Packet Details:**
  * Double-clicked on individual packets to view detailed information within the Wireshark interface.
  * Explored the various subtrees like Frame, Ethernet II, Internet Protocol Version 4, and Transport Control Protocol (TCP) to understand data at different network layers.
  * Identified protocol types, source/destination ports, flags, and other relevant information for individual packets.

**Examining DNS Traffic:**
  * Used filters to isolate DNS traffic on port 53 (udp.port == 53).
  * Analyzed DNS queries (website names being looked up) within the Domain Name System (query) subtree.
  * Interpreted DNS answers containing IP addresses associated with the queried website names.

**Exploring TCP Traffic:**
  * Filtered traffic based on TCP port 80, commonly used for web traffic (tcp.port == 80).
  * Examined properties like Time to Live, Frame Length, Header Length, and Destination Address within the relevant subtrees.
  * Used filters to search for specific text data within TCP payload content (tcp contains "curl").

These skills provide a valuable foundation for further exploration of network traffic using Wireshark. Analyzing network traffic helps security professionals identify potential threats, troubleshoot network issues, and understand network communication patterns.

## Tools Used

**Wireshark:** A free and open-source network protocol analyzer (packet sniffer) used to capture, analyze, and visualize network traffic.

## Steps
### Task 1. Explore data with Wireshark
In this task, you must open a network packet capture file that contains data captured from a system that made web requests to a site. You need to open this data with Wireshark to get an overview of how the data is presented in the application.
    * ![Wireshark 1](https://github.com/user-attachments/assets/5fc4ec16-3000-4264-8c4b-88eb125bfafd)

**2. Scroll down the packet list until a packet is listed where the info column starts with the words 'Echo (ping) request'.**
    * What is the protocol of the first packet in the list where the info column starts with the words 'Echo (ping) request'?
      * ICMP is the protocol type listed for the first (and all) packets that contain 'Echo (ping) request' in the info column.

### Task 2. Apply a basic Wireshark filter and inspect a packet
In this task, you’ll open a packet in Wireshark for more detailed exploration and filter the data to inspect the network layers and protocols contained in the packet.
  * ![Wireshark 2](https://github.com/user-attachments/assets/5ecff3fb-c515-43d2-ad26-e66386a8902e)
  * What is the TCP destination port of this TCP packet?
    * Port 80 is the TCP destination port for this packet. It contains the initial web request to an HTTP website that will typically be listening on TCP port 80.

### Task 3. Use filters to select packets
In this task, you’ll use filters to analyze specific network packets based on where the packets came from or where they were sent to. You’ll explore how to select packets using either their physical Ethernet Media Access Control (MAC) address or their Internet Protocol (IP) address.

**1. Filter to select traffic for IP address:**
  * ip.src == 142.250.1.139
  * ![Wireshark 3](https://github.com/user-attachments/assets/6086d2b0-246f-435b-ae15-2c6f02aeb879)

**2. Filter to select traffic for a specific destination IP address:**
  * ip.dst == 142.250.1.139
  * ![Wireshark 7](https://github.com/user-attachments/assets/71323dbd-adff-4bfd-ac03-9577700b49fe)


**3. Filter to select traffic for a specific Ethernet MAC address:**
  * eth.addr == 42:01:ac:15:e0:02
  * ![Wireshark 8](https://github.com/user-attachments/assets/24d690f7-166e-4ee2-9ebe-6cab9d799e48)

### Task 4. Use filters to explore DNS packets
In this task, you’ll use filters to select and examine DNS traffic. Once you‘ve selected sample DNS traffic, you’ll drill down into the protocol to examine how the DNS packet data contains both queries (names of internet sites that are being looked up) and answers (IP addresses that are being sent back by a DNS server when a name is successfully resolved).
**1.select UDP port 53 traffic. DNS traffic uses UDP port 53, so this will list traffic related to DNS queries and responses only.**
  * udp.port == 53
  * ![Wireshark 4](https://github.com/user-attachments/assets/386da1e0-abc1-42f1-a63f-93c9f3e8a393)
    * Which of these IP addresses is displayed in the expanded Answers section for the DNS query for opensource.google.com?
    * The IP address 142.250.1.139 is displayed in the expanded Answers section for the DNS query for opensource.google.com.

### Task 5. Use filters to explore TCP packets
In this task, you’ll use additional filters to select and examine TCP packets. You’ll learn how to search for text that is present in payload data contained inside network packets. This will locate packets based on something such as a name or some other text that is of interest to you.
**1. Filter to select TCP port 80 traffic. TCP port 80 is the default port that is associated with web traffic:**
  * tcp.port == 80
  * ![Wireshark 5](https://github.com/user-attachments/assets/730df6a0-c08f-46a1-b0a8-fba56873b297)
    * What is the Time to Live value of the packet for IP address '169.254.169.254'?
      * The Time to Live value is 64. This property is contained in the Internet Protocol Version 4 subtree, which is the third subtree listed in the detailed packet inspection window.
      * ![Wireshark 9](https://github.com/user-attachments/assets/8769eb86-b32c-46a6-bcd5-a3a5eefcc412)
    * What is the Frame Length of the packet as specified in the Frame subtree?
      * The Frame Length is 54 bytes. This property is contained in the Frame subtree, which is the first subtree listed in the detailed packet inspection window.
      * ![Wireshark 10](https://github.com/user-attachments/assets/95e7cf4a-7296-4827-9de5-a8b0f5c539bf)
    * What is the Header Length of the packet as specified in the Internet Protocol Version 4 subtree?
      * The Header Length is 20 bytes. This property is defined in the Internet Protocol Version 4 subtree, which is the fourth subtree listed in the detailed packet inspection window.
      * ![Wireshark 11](https://github.com/user-attachments/assets/34a3c952-727a-4c51-94f7-f69f1f98466d)
    * What is the Destination Address as specified in the Internet Protocol Version 4 subtree?
      * The Destination Address is 169.254.169.254. This property is defined in the Internet Protocol Version 4 subtree, which is the third subtree listed in the detailed packet inspection window.
      * ![Wireshark 12](https://github.com/user-attachments/assets/3e3e2328-cbab-4acf-b7ef-95d9b4ffa103)
**2. Enter the following filter to select TCP packet data that contains specific text data.**
  * Filter to select TCP packet data that contains specific text 'curl' data.
      * ![Wireshark 13](https://github.com/user-attachments/assets/81187a41-6ced-464d-83a5-5d97e7668543)
      * This filters to packets containing web requests made with the curl command in this sample packet capture file.

### Summary

This lab provided hands-on experience in using Wireshark to analyze network traffic. Key skills acquired include:

* Opening and examining packet capture files.
* Filtering network traffic based on various criteria, such as IP addresses, ports, and protocol types.
* Inspecting packet details, including source and destination addresses, protocols, and payload data.
* Analyzing DNS traffic to identify domain name queries and IP address resolution.
* Searching for specific text patterns within packet payloads.

By mastering these skills, users can effectively investigate network security incidents, troubleshoot network issues, and gain valuable insights into network behavior.
