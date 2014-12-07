Comp. 116 - Security
Assignment 5 - Forensics
12/4/2014

Inbar Fried and Louis Ades

We did a checksum to make sure that the downloaded and extracted files had consistent keys
to the keys provided on the assignment website.

Part 1

1. We used the 'diff' command on the terminal to determine which image is different between
   a.jpg, b.jpg, and c.jpg.
   We determined that b.jpeg was different.
   We then ran a python script (included in the submission) to crack the passphrase.
   Upon entering the correct passphrase, a file titled "runme" was extracted from the image.
   The passphrase is "disney".

Part 2

1. The disk format of the disk on the suspect's computing device are Windows95 FAT32 and
   Linux. This was revealed by Autopsy under the 'disk.dd' header.

2. We do not believe that there is a phone carrier involved. We have found a file containing
   a list of mobile broadband providers "mobile-broadband-provider-info" in /usr/share
   and .mp3 files titled "ringtone" and "Phone.wav" inside the "Audio" folder provided
  by Autopsy, but there seems to be no direct reference to a single provider.
   In the Windows disk there is a file 'LICENCE.broadcom', and the Broadcom company is
   a service provider, but not necessarily to phones. The file seems to be intended for a Raspberry Pi device.

3. The operating system is Kali Linux and the version number is 1.0.9. We determined
   this information from the file etc/debian_version.

4. The applications installed on this disk include:
    - WireShark
    - Apache2
    - Avahi
    - Firebird
    - Emacs
    - Ice Weasel
    - John
    - Python2.7
    - Perl
    - MySQL
    - PulseAudio
    - ImageMagick
    These were found in /etc.
    We also found:
     - Nmap
     - Aircrack-ng
     - Hydra
     and a lot of other Kali applications.
    These were found in /usr/share/applications.
	We determined this by looking through the Autopsy GUI.

5. There is a root password.  It is 'princess'. We found this by unshadowing the
   etc/shadow and etc/passwd files and then passing the unshadowed file to john the ripper.

6. There are additional user accounts on the system.
   The accounts are:
     alejandro
     judas
     stefani
     These were found in /home.
     Their passwords are 'iloveyou' for stefani, '00000000' for judas, and 'pokerface' for alejandro.
     We found these passwords by:
      1) taking the etc/shadow and etc/passwd files and unshadowing them.
      2) passing the unshadowed file to john the ripper.
     The password 'pokerface' was found using a self-made wordlist of Lady Gaga
     song titles and her legal name.

7. Some of the incriminating evidence we found includes:
    - Photos of Lady Gaga (found in the user account 'stefani').
    - A video of Lady Gaga performing at NYU when she was a student there (found in
      the the user account 'stefani').
    - There is a schedule of Lady Gaga's performances (found in the user account 'stefani').
    - There is a ringtone of a piano version of "Bad Romance" (found in the user account 'stefani').

8. The suspect did try to delete some files before their arrest.
   The account 'alejandro' deleted a15.jpg, a16.jpg, and a17.jpg. We found rm commands
   in the .bash_history files.
   These are most likely images of Lady Gaga because the files a1.jpg through a14.jpg
   are images of Lady Gaga.

   The account 'stefani' used an rm command to delete the file note.txt. This command
   was found in .bash_history. From the title of the file it is most likely a note the
   suspect left themselves.

9. The suspect did save any pictures of the celebrity. We found 14 pictures of Lady Gaga
   titled a1.jpg through a14.jpg and believe that the three deleted files a15.jpg, a16.jpg,
   and 17.jpg are also images of Lady Gaga. These images were found
   in the user account 'alejandro' and in Autopsy's 'Images' folder.

10. There are encrypted files. The file is '0024' and we found it under the 'Encryption Detected'
    folder in Autopsy. When trying to examine the file in Kali we were able to see that it
    contained a file called 'edge.mp4'. We believe that it is a performance of Lady Gaga's song 'Edge of Glory'.

11. The suspect wants to see the celebrity at three potential venues.
	Venue 1 is The Chelsea at the Cosmopolitan of Las Vegas, in Las Vegas, NV at 9:00 PM PST on 12/31/2014.
	Venue 2 is the Wiltern Theatre, in Los Angeles, CA at 9:30 PM PST on 2/8/2015.
	Venue 3 is the Hollywood Bowl, in Hollywood, CA at 7:30 PM PDT on 5/30/2015.
	This information was found in the file 'sched.txt' that was in the user account 'stefani'.

12. The celebrity is Lady Gaga. Many of the JPEG files are images of Lady Gaga and there is a video recording
    'vintage_nyu_performance.mp4' of her singing at NYU.
