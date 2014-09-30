require 'packetfu'

stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
stream.show_live()