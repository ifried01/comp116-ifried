require 'packetfu'
require 'Slop'

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
# XMAS scan
pkt_array.show_live(:filter => 'tcp[tcpflags] & (tcp-push & tcp-fin & tcp-urg) == (tcp-push & tcp-fin & tcp-urg)')


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

def raiseAlarm(attack, source_IP, protocol, payload)
	puts " #{$alarm_instance_number}. ALERT: #{attack} is detected from #{source_IP} (#{protocol}) (#{payload})!"
	$alarm_instance_number += 1
end

