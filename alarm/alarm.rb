'''
Inbar Fried
Comp. 116 - Fall 2014
Assignment 2 - Alarm
10/7/2014
'''

require 'packetfu'
require 'slop'
require 'base64'

# regex for visa, mastercard, dicover card, and american Express credit cards
$visa        = /4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
$master      = /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
$discover    = /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
$americanExp = /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/
# regex for HTTP 400-499 errors, nmap scans, and Shellcodes
$HTTP400Err  = 'HTTP\/1.1" 4[0-9][0-9]'
$nmapScan    = 'Nmap'
$shellCode   = /(\\x\h\h)+/
# keeps track of how many alerts we have seen (used in raiseAlarm)
$alarm_instance_number = 1

''' ~~~~~~~~~~ Functions to analyze the appropriate input ~~~~~~~~~~ '''
def analyzeLiveNetworkTraffic()
  # capture live stream of network packets
  pkt_array = PacketFu::Capture.new(:start => true, :iface => 'en1', :promisc => true)
  pkt_array.stream.each do |p|
    pkt = PacketFu::Packet.parse(p)
    if pkt.is_ip? and pkt.is_tcp?
      # when all the flags are set to 0, it's a NULL scan
      if pkt.tcp_flags.syn == 0 and pkt.tcp_flags.ack == 0 and pkt.tcp_flags.psh == 0 and pkt.tcp_flags.urg == 0 and pkt.tcp_flags.rst == 0 and pkt.tcp_flags.fin == 0
      	raiseAlarm('NULL scan is detected', pkt.ip_saddr, pkt.proto, Base64.encode64(pkt.payload))
      # when the 'urg', 'psh', and 'fin' flags are set to 1, it's a XMAS scan
  	  elsif pkt.tcp_flags.urg == 1 and pkt.tcp_flags.fin == 1 and pkt.tcp_flags.psh == 1
	 	   raiseAlarm('XMAS scan is detected', pkt.ip_saddr, pkt.proto, Base64.encode64(pkt.payload))
      else
        checkForCreditCards(pkt)
      end
    end
  end
end

def checkForCreditCards(pkt)
  if pkt.payload.match($visa) or pkt.payload.match($master) or pkt.payload.match($discover) or pkt.payload.match($americanExp)
    raiseAlarm('Credict card leaked in the clear', pkt.ip_saddr, 'HTTP', Base64.encode64(pkt.payload))
  end
end

def analyzeWebServerLog(log_file)
  File.open(log_file) do |f|
    f.each_line do |line|
      line_contents = line.strip.split(' ')
      payload       = line.strip.split('"')[1]
      source_IP     = line_contents[0]
      if line.match($HTTP400Err)
        raiseAlarm('HTTP error is detected', source_IP, 'HTTP', payload)
      end
      if line.match($nmapScan)
        raiseAlarm('NMAP scan is detected', source_IP, 'HTTP', payload)
      end
      if payload.match($shellCode)
        raiseAlarm('Shellcode is detected', source_IP, 'HTTP', payload)
      end
    end
  end
end

def raiseAlarm(attack, source_IP, protocol, payload)
  puts " #{$alarm_instance_number}. ALERT: #{attack} from #{source_IP} (#{protocol}) (\"#{payload}\")!"
  $alarm_instance_number += 1
end

''' ~~~~~~~~~~ Main() ~~~~~~~~~~ '''
# read in a web server log instead of live network packets if -r flag is provided
opts = Slop.parse do
  banner 'Usage: alarm.rb [options]'
  on 'r=', 'web_server', 'Read Web Server Log'
end

# if the -r flag was provided
if opts.web_server?
  ''' Running with web server log '''
  analyzeWebServerLog(opts[:web_server])
else
  ''' Running live network traffic '''
  analyzeLiveNetworkTraffic()
end