Inbar Fried
9/12/2014
Comp 116 - Security
Fall 2014
Assignment 1

set1.pcap

1. How many packets are there in this set?  
      *1503

2. What protocol was used to transfer files from PC to server?  
      HTTP

3. Briefly describe why the protocol used to transfer the files is insecure?  
      The files transferred are not encrypted by a secure certificate and third parties  
      can therefore intercept information and view it.  

4. What is the secure alternative to the protocol used to transfer files?  
      HTTPS  

5. What is the IP address of the server?  
      67.23.79.113

6. What was the username and password used to access the server?  
      USER ihackpineapples  
      PASS rockyou1

7. How many files were transferred from PC to server?  
      4

8. What are the names of the files transferred from PC to server?  
      BjN-01hCAAAZbiq.jpg  
      BvgT9p2IQAEEoHu.jpg  
      BvzjaN-IQAA3XG7.jpg  
      smash.txt

9. Extract all the files that were transferred from PC to server. These files must be part of your submission!  
      Attached :)

set2.pcap  

10. How many packets are there in this set?  
          77882

11. How many plaintext username-password pairs are there in this packet set?  
          9

12. Briefly describe how you found the username-password pairs.  
        Using the terminal command "sudo ettercap -T -r set2.pcap | grep "PASS:"  
        dsniff -p set2.pcap  
        Searching for the string "pass" in packet details in WireShark.

13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.  
          chris@digitalinterlude.com  
          Volrathw69 (valid)  
            Protocol: POP  
            Server IP: 75.126.75.131  
            Domain Name: si-sv3231.com  
            Port Number: 110  
        cisco  
        184 yomama1  
            Protocol: TELNET  
            Server IP: 200.60.17.1  
            Domain Name:  
            Port Number: 23  
        cisco 
        185 12345d (invalid)  
            Protocol: TELNET  
            Server IP: 200.60.17.1  
            Domain Name:  
            Port Number: 23  
        cisco  
        185 122333 (invalid)  
            Protocol: TELNET  
            Server IP: 200.60.17.1  
            Domain Name:   
            Port Number: 23  
        cisco  
        185 august23 (invalid)  
            Protocol: TELNET  
            Server IP: 200.60.17.1  
            Domain Name:   
            Port Number: 23  
        cisco  
        185 anthony7 (invalid)  
            Protocol: TELNET  
            Server IP: 200.60.17.1  
            Domain Name:   
            Port Number: 23  
        cisco  
        185 allahu (invalid)  
            Protocol: TELNET  
            Server IP: 200.60.17.1  
            Domain Name:   
            Port Number: 23  
        cisco  
        185 alannah (invalid)  
            Protocol: TELNET  
            Server IP: 200.60.17.1  
            Domain Name:   
            Port Number: 23  
        cisco  
        185 BASKETBALL (invalid)  
            Protocol: TELNET  
            Server IP: 200.60.17.1  
            Domain Name:   
            Port Number: 23  
            
14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted?  
      1

15. How did you verify the successful username-password pairs?  
      I followed the TCP stream and looked if the password had been accepted.

16. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?  
      Whenever entering your password (or any sensitive information) to a website, make sure that there is an HTTPS protocol associated with the URL!
