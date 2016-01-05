# PacketNgin IPSec

## CLI

###COMMANDS

####Manage network interface ip
	ip -- Manage ip of network interface interface.
######SUB COMMANDS
	add [interface][address]-- Allocate ip to network interface.
	remove -- Free ip from network interface.

####Manage network interface ip
	route -- Manage ip of network interface interface.
######SUB COMMANDS
	add [interface][address]-- Allocate ip to network interface.
	remove [interface][address]-- Free ip from network interface.
######PARAMETERS
	-g gateway
	-m mask
		Mas specification.
		default 24

####Manage Security policy
	sp -- Manages SPD(Security Policy Database) entries in interface.
######SUB COMMANDS
	add [interface][protocol][source][destination][action][index] -- Add SP.
	remove [interface][direction][index] -- Remove SP.
	list [interface] -- Print list of SP.
######PARAMETERS
	-p Protocols
		Protocol specification.
		any -- TCP & UDP
		tcp -- TCP
		udp -- UDP
		default protocol = any

	-s [address][/mask][:port]
		Source specification.
		default address = any
		default mask = 32
		default port = any

	-d [address][/mask][:port]
		Destination specificiation.
		default address = any
		default mask = 24
		default port = any

	-a actions[/direction]
		ipsec -- IPSec action
		bypass -- Bypass action
		default action = bypass
		out -- out bound
		in -- in bound
		default direction = out

	-direction direction
		out -- outbound
		in -- inbound

	-i index
		Index of entry.
		default index = 0

	-o out network interface

####Manages contents
	content -- Manages contents in SP.
######SUB COMMANDS
	add [interface][SP index]-- Add content to SP.
	remove [interface][SP index]-- Remove content from SP.
	list [interface][SP index]-- Print list of contents in SP.
######PARAMETERS
	-m mode
		tunnel[source address-destination address] -- tunnel mode
		transport -- transport mode

	-E encapsulating security payload method
		des_cbc
		3des_cbc
		blowfish_cbc
		cast128_cbc
		rijndael_cbc
		camellia_cbc
		aes_ctr
		twofish_cbc -- not yet support
		des_deriv -- not yet support
		3des_deriv -- not yet support

	-A authentication method
		hmac_md5
		hmac_sha1
		hmac_sha256
		hmac_sha384
		hmac_sha512
		hmac_ripemd160
		keyed_md5 -- not yet support
		keyed_sha1 -- not yet support
		aes_xcbc_mac -- not yet support
		tcp_md5 -- not yet support

	-i index
		Index of entry.
		default index = 0

####Manage security association
	sa -- Manage SA(Security Association) entries.
######SUB COMMANDS
	add [interface] -- Add security association entry
	remove [interface][destination][ipsec_protocol][spi] -- Remove security association entry
	list [interface] --List security association entry

######PARAMETERS
	-p Protocols
		Protocol specification.
		any -- TCP & UDP
		tcp -- TCP
		udp -- UDP
		default protocol = any

	-s [address][/mask][:port]
		Source specification.
		default address = any
		default mask = 32
		default port = any

	-d [address][/mask][:port]
		Destination specificiation.
		default address = any
		default mask = 24
		default port = any

	-E encapsulating security payload method[key: HEX][spi: HEX]
		des_cbc -- key length: 8 Bytes
		3des_cbc -- key length: 24 Bytes
		blowfish_cbc -- key length: 5 ~ 56 Bytes
		cast128_cbc -- key length: 5 ~ 16 Bytes
		rijndael_cbc -- key length: 16, 24, 32 Bytes
		camellia_cbc -- key length: 16, 24, 32 Bytes
		aes_ctr -- key length: 16
		twofish_cbc -- not yet support
		des_deriv -- not yet support
		3des_deriv -- not yet support

	-A authentication method[key: HEX][spi: HEX]
		hmac_md5 -- key length: 16 Bytes
		hmac_sha1 -- key length: 20 Bytes
		hmac_sha256 -- key length: 32 Bytes
		hmac_sha384 -- key length: 48 Bytes
		hmac_sha512 -- key length: 64 Bytes
		hmac_ripemd160 -- key length: 20 Bytes
		keyed_md5 -- not yet support
		keyed_sha1 -- not yet support
		aes_xcbc_mac -- not yet support
		tcp_md5 -- not yet support

###EXAMPLES1
	ip add eth1 10.0.0.1
	ip add eth0 192.168.100.253

	sp add eth0 -p any -s 192.168.100.0/24:0 -d 192.168.101.0/24:0 -a ipsec/out -i 0 -o eth1
	content add eth0 out 0 -m tunnel 10.0.0.1-10.0.0.2 -A hmac_md5 -i 0

	sp add eth1 -p any -s 192.168.101.0/24:0 -d 192.168.100.0/24:0 -a ipsec/in -i 0 -o eth0
	content add eth1 in 0 -m tunnel 10.0.0.2-10.0.0.1 -A hmac_md5 -i 0

	sa add eth0 -p any -s 192.168.100.0/24:0 -d 192.168.101.0/24:0 -m tunnel 10.0.0.1-10.0.0.2 -spi 0x200 -A hmac_md5 0x0123456789abcdef0123456789abcdef
	sa add eth1 -p any -s 192.168.101.0/24:0 -d 192.168.100.0/24:0 -m tunnel 10.0.0.2-10.0.0.1 -spi 0x201 -A hmac_md5 0x0123456789abcdef0123456789abcdef

###EXAMPLES2
	sp remove eth0 -direction out -i 0
	sp remove eth1 -direction in -i 0
	
	sa remove eth0 -d 192.168.101.0/24:0 -p ah -spi 0x200
	sa remove eth1 -d 192.168.100.0/24:0 -p ah -spi 0x201

# License
	PacketNgin IPsec is distributed under GPL2 license.
