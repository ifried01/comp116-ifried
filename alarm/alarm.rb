require 'packetfu'
require 'Slop'
require 'snort-rule'

$alarm_instance_number = 1

# read in a web server log instead of live network packets if -r flag is provided
opts = Slop.parse do
  banner 'Usage: alarm.rb [options]'
  on 'r=', 'web_server', 'Read Web Server Log'
end

# if the -r flag was provided
if opts.web_server?
	# web_server_file = opts[:web_server]
	puts "Running with web server log"
else
	puts "Running live network traffic"
end

# capture live stream of network packets

pkt_array = PacketFu::Capture.new(:start => true, :iface => 'en1', :promisc => true)
pkt_array.stream.each do |p|
  pkt = PacketFu::Packet.parse(p)
  if pkt.is_ip? and pkt.is_tcp? 
    if pkt.tcp_flags.syn == 0 and pkt.tcp_flags.ack == 0 and pkt.tcp_flags.psh == 0 and pkt.tcp_flags.urg == 0 and pkt.tcp_flags.rst == 0 and pkt.tcp_flags.fin == 0
    	raiseAlarm('NULL', pkt.ip_saddr, pkt.proto, pkt.payload)
	  elsif pkt.tcp_flags.urg == 1 and pkt.tcp_flags.fin == 1 and pkt.tcp_flags.psh == 1
		  raiseAlarm('XMAS', pkt.ip_saddr, pkt.proto, pkt.payload)
    end
  end
end

pkt_array.show_live(:filter => 'tcp[tcpflags] & (tcp-push & tcp-fin & tcp-urg) == (tcp-push & tcp-fin & tcp-urg)')

def raiseAlarm(attack, source_IP, protocol, payload)
  puts " #{$alarm_instance_number}. ALERT: #{attack} is detected from #{source_IP} (#{protocol}) (#{payload})!"
  $alarm_instance_number += 1
end

=begin
# convert caught packet streams from string to PacketFu packet
caught = false
while caught == false do
	pkt_array.stream.each do |p|
		if PacketFu::Packet.has_data?
			pkt = PacketFu::Packet.parse(p)
		end
	end
end
=end

      #print "Source Addr: #{pkt.ip_saddr}\n"
      #print "Destination Addr: #{pkt.ip_daddr}\n"
      #print "Destination Port: #{pkt.tcp_dport}\n"
      #print "TCP Options: #{pkt.tcp_options}\n"
      #print "TCP SYN?: #{pkt.tcp_flags.syn}\n"
      #print "TCP ACK?: #{pkt.tcp_flags.ack}\n"

