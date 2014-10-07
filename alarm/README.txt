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
		one-solution issue. We need to detect hexadecimal in the , but
		hexadecimal shows up in many packages that are not actuall ShellCode.
		In this implementation I only match on payloads that begin with
		hexadecimal exclusively.

5) If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
	~ I would add further specifications to checks like credit card detection in
	  order to detect with payloads that are really sophisticated.
	  I would also add a learning method that would block certain IPs after getting
	  attempted intrusions from the specific IP.
	  
	  On another note, once an incident is detected, it might be too late
	  to treat the issue. To fix this issue, we need to address the cause.


