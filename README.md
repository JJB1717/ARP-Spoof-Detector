# ARP-Spoof-Detector
BEGIN:
Input: ARP request packet.
Output: ARP reply packet.

Step1: Before sending ARP Reply Frame, the dest. host will
Step2: check the IP address of the source host in its firewall.
Step3: if (firewall contains IP address), then
Step4: A message will display directly to the dest. host
Step5: show alert message this IP is blocked
Step6: else
Step7: checking for any types of attacks ARP Request packet
Step8: If ( the packet is an ARP packet and ARP reply (op=2), then
Step9: get the real MAC address of the sender and response MAC from the ARP Reply packet
Step10: if they”re different, definitely there is an attack
Step11: If (NOT match), then
Step12: show alert message in dest. host “under attack” and IP the attacker
Step13: blocking this attacker from all protocols in dest. host
Step14: block this IP
Step15: do reverse attack on attacker host to cut service
Step16: reverse attack on attacker
Step17: else
        ARP Reply Frame will be sent to the source host.
END: //end of the procedure
