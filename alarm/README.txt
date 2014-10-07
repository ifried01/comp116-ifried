Inbar Fried
Comp. 116 - Fall 2014
10/7/2014
Assignment 2 - Incident Alarm with Ruby and PacketFu

1) Aspects that have been correctly implemented?
	~ To my knowledge, all aspects have been correctly implemented.

2) Collaborated with:
	~ Ming Chow

3) Hours spent on assignment:
	~ 8-10 hours

4) Are the heuristics used in this assignment to determine inicidents "even that good"?
	~ No. Detecting ShellCode, for example, is definitely not a direct and
		one-solution issue. We need to detect hexadecimal in the payload, but
		hexadecimal shows up in many packages that are not actuall ShellCode.
		In this implementation I only match on payloads that begin with
		hexadecimal exclusively.

5) If you have spare time in the future, what would you add to the program or do
   differently with regards to detecting incidents?
	~ I would add further specifications to detections like credit card detection in
	  order to detect payloads that are really sophisticated, such as polymorphic code.
	  I would also add a learning method that would block certain IPs after getting
	  attempted intrusions from the specific IP.
	  
	  On another note, once an incident is detected, it might be too late
	  to treat the issue. To fix this issue, we need to address the cause of the
	  vulnerability.

NOTE
	- In my implementation of the web server log scanning, if a single packet is
	  both an HTTP 400-range issue, and an NMAP issue, for example, I will raise
	  two alerts. One alert will be regarding the HTTP 400-range issue and the other
	  alert will be regarding the NMAP issue.