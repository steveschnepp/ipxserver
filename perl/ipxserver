#!/usr/bin/perl
# Found at http://stuff.digriz.org.uk/ipxserver
# See copyright at the end.

=head1 NAME

ipxserver - standalone dosbox IPX server

=head1 DESCRIPTION

B<ipxserver> provides an alternative to the built in dosbox
IPXNET server that can be run on any UNIX box that has Perl
installed.  The main advantages being that it runs standalone
and if run as root it can listen on port 213/udp (the IANA
assigned port for IPX over IP tunnelling).

=cut

use strict;
use warnings;

use Getopt::Long qw/:config no_ignore_case/;
use Pod::Usage;
use File::Basename;
use Sys::Syslog qw/:standard :macros/;
use POSIX qw/setsid/;
use Socket;
use IO::Socket::INET;

#use Data::Dumper;

my $VERSION = '20100124';

my @DEBUG = (
	LOG_EMERG,	# system is unusable
	LOG_ALERT,	# action must be taken immediately
	LOG_CRIT,	# critical conditions
	LOG_ERR,	# error conditions
	LOG_WARNING,	# warning conditions
	LOG_NOTICE,	# normal, but significant, condition
	LOG_INFO,	# informational message
	LOG_DEBUG	# verbose-level message
);

=head1 OPTIONS

=over 4

=item B<-h, --help>

Print a brief help message and exits.

=item B<--man>

Print complete manpage and exits.

=item B<-V, --version>

Print version number and exit.

=item B<-v>

Make more verbose (state multiple '-v's for more verbosity).

=item B<-q>

Make more quiet (state multiple '-q's for less verbosity).

=item B<-l num, --log=num>

Set the syslog local facility (default '0'), valid values
range from 0 to 7 inclusively.

=item B<-p num, --port=num>

Set UDP port to listen on (default 213), values below 1024
require this program to be run as root.

=item B<-u user, --user=user>

If running as root then after opening UDP port drop privileges
to unprivileged user account (default 'nobody').

=item B<-i secs, --idle=secs>

As there is no concept of disconnecting with IPXNET we have to
idle out the connections instead.  With this you can set the
timeout value (default 1800).

=item B<-n, --no-fork>

Do not fork the program as a daemon, and additionally logs to
STDERR.

=back

=cut

my $port = getservbyname('ipx', 'udp') || 213;
my %opts = (
	v	=> 0,
	q	=> 0,

	l	=> 0,
	p	=> $port,
	u	=> 'nobody',
	i	=> 1800,
);
GetOptions(
	'h|help'	=> sub { pod2usage(-exitval => 0) },
	'man'		=> sub { pod2usage(-exitval => 0, -verbose => 2) },
	'V|version'	=> sub { pod2usage(-exitval => 0, -message => "ipxserver - version $VERSION\n") },

	'v+'		=> \$opts{'v'},
	'q+'		=> \$opts{'q'},

	'l|log=i'	=> \$opts{'l'},
	'p|port=i'	=> \$opts{'p'},
	'u|user=s'	=> \$opts{'u'},
	'i|idle=i'	=> \$opts{'i'},

	'n|no-fork'	=> \$opts{'n'},
) || pod2usage(2);

die 'invalid facility log value (0 <= n < 8)'
	unless ($opts{'l'} >= 0 && $opts{'l'} < 8);
die 'invalid port number to listen on (0 < n < 65536)'
	unless ($opts{'p'} > 0 && $opts{'p'} < 65536);

if (defined($opts{'n'})) {
	openlog(basename($0), 'ndelay|pid|perror', "local$opts{'l'}");
}
else {  
	# perlfaq8 - How do I fork a daemon process?
	my $sid = setsid;
	chdir '/';

	open STDIN,  '+>/dev/null';
	open STDOUT, '+>&STDIN';
	open STDERR, '+>&STDIN';

	my $pid = fork;
	die "unable to fork() as daemon: $!"
		unless (defined($pid));

	exit 0 if ($pid != 0);

	openlog(basename($0), 'ndelay|pid', "local$opts{'l'}");

	syslog LOG_NOTICE, 'started';
}

if (5+$opts{'v'}-$opts{'q'}>=scalar(@DEBUG)) {
	setlogmask(LOG_UPTO(LOG_DEBUG));
} elsif (5+$opts{'v'}-$opts{'q'}<0) {
	setlogmask(LOG_UPTO(LOG_EMERG));
} else {
	setlogmask(LOG_UPTO($DEBUG[5+$opts{'v'}-$opts{'q'}]));
}

my $sock = &openSocket();
exit 1 unless ($sock);

# TODO use Net::UPnP to request the port fowarding

# lets make 'ps'/'netstat' look prettier
$0 = basename($0);

# no longer need root
if ($< == 0 || $> == 0) {
	$< = $> = getpwnam $opts{'u'};
	syslog LOG_WARNING, "unable to drop root uid priv: $!"
		if ($!);
}
#if ($( == 0 || $) == 0) {
#	$( = $) = getgrnam $opts{'u'};
#	syslog LOG_WARNING, "unable to drop root gid priv: $!"
#		if ($!);
#}

# the server address does not really matter, so we pick 0.0.0.0
# as it is impossible that anything else would use this
my $ipxSrvNode = unpack('H12', inet_aton('0.0.0.0') . pack('n', $opts{'p'}));

my (%clients, %ignore);
my $running = 1;
my $lastTs = time;

$SIG{'INT'}=$SIG{'TERM'}=\&sigTERM;
$SIG{'HUP'}=\&sigHUP;

while ($running) {
	# IPX packet cannot be bigger than 1500 - 40(ip) - 8(udp)
	my $srcpaddr = $sock->recv(my $payload, 1452, 0);

	# if there has been a signal, this is undef
	next unless ($srcpaddr);

	my $ts = time;
	if ($lastTs < $ts - 600) {
		# to simplify the code (and to reduce possible spoofed
		# disconnects), instead of listening for ICMP unreachables
		# we simply timeout the connections which we would have to
		# do anyway to mop up regularly disconnected users, as the
		# clients do not inform the server when they go away. 
		foreach my $client (keys %clients) {
			next if ($clients{$client}{'ts'} > $ts - $opts{'i'});

			syslog LOG_INFO, '[' . $clients{$client}{'ip'} . ']'
						. ' idle timeout for '
						. $clients{$client}{'node'};
			delete $clients{$client};
		}

		# every interval we check what we can mop up
		delete $ignore{$_}
			for grep { $ignore{$_} < $ts - 600 } keys %ignore;

		$lastTs = $ts;
	}

	my ($srcport, $srciaddr) = sockaddr_in $srcpaddr;
	my $srcaddr = inet_ntoa $srciaddr;

	my $d = &ipxDecode($srcaddr, $payload);
	next unless (defined($d));

	#print Dumper $d;

	my $respond = ($d->{'dst'}{'node'} eq $ipxSrvNode
			|| $d->{'dst'}{'node'} eq 'ffffffffffff');
	# registration packet
	if (!$respond && &isReg($d)) {
		# we *cannot* delete the previous registeration otherwise
		# this gives bad users a perfect opportunity to effectively
		# kick others off.  The other, although unlikely, cause is
		# if the client OS (or NAT) re-uses the same source port.
		if (defined($clients{"$srcaddr:$srcport"})) {
			syslog LOG_WARNING, "[$srcaddr] re-registration, possibly spoofed DoS attempt";
			next;
		}

		&register(\%clients, $ts, $srcaddr, $srcport);
		$respond = 1;
	}
	else {
		unless (defined($clients{"$srcaddr:$srcport"})) {
			syslog LOG_WARNING, "[$srcaddr] packet(s) from unregistered source"
				unless (defined($ignore{$srcaddr}));
			$ignore{$srcaddr} = $ts;
			next;
		}

		# reverse path filtering
		unless ($d->{'src'}{'node'} eq $clients{"$srcaddr:$srcport"}{'node'}) {
			syslog LOG_ERR, "[$srcaddr] reverse path filtering failure(s)"
				unless (defined($ignore{$srcaddr}));
			$ignore{$srcaddr} = $ts;
			next;
		}

		$clients{"$srcaddr:$srcport"}{'ts'} = $ts;

		syslog LOG_DEBUG, "[$srcaddr] pkt " . $d->{'src'}{'node'}
					. ' > ' . $d->{'dst'}{'node'};

		my @dest = ($d->{'dst'}{'node'} eq 'ffffffffffff')
			? grep { $clients{$_}{'node'} ne $d->{'src'}{'node'} }
				keys %clients
			: grep { $clients{$_}{'node'} eq $d->{'dst'}{'node'} }
				keys %clients;

		# N.B. we do not increment transport control as really
		#	we are acting as a switch
		# TODO handle errors (mtu?) rather than just report them
		foreach my $dst (@dest) {
			my $n = $sock->send($payload, MSG_DONTWAIT,
						$clients{$dst}{'paddr'});
			unless (defined($n)) {
				syslog LOG_ERR, '[' . $clients{$dst}{'ip'} . ']'
						. 'unable to sendto()';
				next;
			}
			unless ($n == length($payload)) {
				syslog LOG_ERR, '[' . $clients{$dst}{'ip'} . ']'
						. 'unable to sendto() complete payload';
				next;
			}
		}
	}

	next unless ($respond);

	# ping
	if ($d->{'src'}{'sock'} == 2 && $d->{'dst'}{'sock'} == 2) {
		# registration hack
		syslog LOG_INFO, "[$srcaddr] echo req from " . $d->{'src'}{'node'}
			unless ($d->{'src'}{'node'} eq '000000000000');

		my $reply = pack 'nnCCH8H12nH8H12na*',
			0xffff, 30, 0, 2,
			'00000000', $clients{"$srcaddr:$srcport"}{'node'}, 2,
			'00000000', $ipxSrvNode, 2;

		# N.B. we do not check that the whole packet has been sent,
		#	as we have bigger problems if we cannot send a
		#	30 byte payload
		# TODO handle errors (mtu?) rather than just report them
		my $n = $sock->send($reply, MSG_DONTWAIT,
					$clients{"$srcaddr:$srcport"}{'paddr'});
		unless (defined($n)) {
			syslog LOG_ERR, "[$srcaddr] unable to sendto()";
			next;
		}
	}
}

$sock->close;

syslog LOG_NOTICE, 'exited';

exit 0;

sub sigTERM {
	my $signal = shift;

	if ($running) {
		syslog LOG_NOTICE, "caught SIG$signal...shutting down";
		$running = 0;
	}
};
sub sigHUP {
	my $signal = shift;

	syslog LOG_NOTICE, "caught SIGHUP, disconnecting all clients";
	%clients = ();
}

sub openSocket {
	my %args = (
		LocalPort	=> $opts{'p'},
		Proto		=> 'udp'
	);

# as dosbox is not v6 enabled... :-/
#	eval {
#		require Socket6;
#		require IO::Socket::INET6;
#	};
#	my $sock = ($@)
#		? IO::Socket::INET->new(%args)
#		: IO::Socket::INET6->new(%args);
	my $sock = IO::Socket::INET->new(%args);
	
	unless (defined($sock)) {
		syslog LOG_CRIT, "could not open udp socket: $!";
		return;
	}

	return $sock;
}

sub ipxDecode {
	my $srcaddr = shift;
	my $packet = shift;

	unless (length($packet) >= 30) {
		syslog LOG_WARNING, "[$srcaddr] packet too short";
		return;
	}

	my %d;
	($d{'cksum'}, $d{'len'}, $d{'hl'}, $d{'type'},
		$d{'dst'}{'net'}, $d{'dst'}{'node'}, $d{'dst'}{'sock'},
		$d{'src'}{'net'}, $d{'src'}{'node'}, $d{'src'}{'sock'},
		$d{'payload'} ) = unpack 'nnCCH8H12nH8H12na*', $packet;

	unless (defined($d{'payload'})) {
		syslog LOG_WARNING, "[$srcaddr] unable to unpack() packet";
		return;
	}

	unless ($d{'cksum'} == 0xffff) {
		syslog LOG_WARNING, "[$srcaddr] cksum != 0xffff";
		return;
	}
	unless ($d{'len'} == 30 + length($d{'payload'})) {
		syslog LOG_WARNING, "[$srcaddr] length != header + payload";
		return;
	}
	unless ($d{'src'}{'net'} eq '00000000') {
		syslog LOG_WARNING, "[$srcaddr] src not net zero traffic";
		return;
	}
	unless ($d{'dst'}{'net'} eq '00000000') {
		syslog LOG_WARNING, "[$srcaddr] dst not net zero traffic";
		return;
	}
	# HACK clause for the registration packets
	if ($d{'src'}{'node'} eq $d{'dst'}{'node'} && !&isReg(\%d)) {
		syslog LOG_ERR, "[$srcaddr] LAND attack packet";
		return;
	}

	return \%d;
}

sub isReg {
	my $d = shift;

	# we ignore 'type' as it seems that:
	#  * dosbox 0.72 => type = (not initialised - garbage)
	#  * dosbox 0.73 => type = 0
	return ($d->{'hl'} == 0 && $d->{'len'} == 30
			&& $d->{'src'}{'net'} eq $d->{'dst'}{'net'}
			&& $d->{'src'}{'node'} eq $d->{'dst'}{'node'}
			&& $d->{'src'}{'sock'} == $d->{'dst'}{'sock'}
			&& $d->{'src'}{'net'} eq '00000000'
			&& $d->{'src'}{'node'} eq '000000000000'
			&& $d->{'src'}{'sock'} == 2);
}

sub register {
	my $clients = shift;
	my $ts = shift;
	my $srcaddr = shift;
	my $srcport = shift;

	# rfc1234 does not seem to be completely NAT safe so we
	# include the src port too, also makes 'ipxnet ping' pretty
	my $node = unpack('H12', inet_aton($srcaddr) . pack('n', $srcport));
	my $paddr = sockaddr_in $srcport, inet_aton($srcaddr);

	# TODO connected bad guys can deduce the UDP src port and addr
	#	of other clients and spoof packets from them if there
	#	is no egress rpf at the end (or same subnet).  A fix
	#	for this would be to make the node addres a folded HMAC
	#	(however, although trivial, it might not be worth doing).
	#	If we end up doing this, it probably is safe to pay
	#	attention to those 'ICMP unreachable' messages that come
	#	back when we have a disconnected client
	$clients->{"$srcaddr:$srcport"} = {
		ip	=> $srcaddr,
		port	=> $srcport,

		node	=> $node,
		paddr	=> $paddr,
		ts	=> $ts,
	};

	syslog LOG_NOTICE, "[$srcaddr] registered client $node";
}

__END__

=head1 SYNOPSIS

ipxserver [options]

=over 4

=item disconnect all clients

pkill -HUP ipxserver

=item shutdown

pkill ipxserver

=back

=head1 CHANGELOG

=over 4

=item B<20100123>

First version conceived.

=item B<20100124>

Removed the '$d{'hl'} == 0' sanity check, GTA trips on this.
Added a logging throttling mechanism for unknown hosts and
RPF failures.

=back

=head1 SEE ALSO

It is worth going over to L<http://www.dosbox.com/wiki/IPX> to
read up about IPX networking with dosbox.

=head1 COPYRIGHT

ipxserver - standalone dosbox IPX server

Copyright (C) 2010 Alexander Clouter <alex@digriz.org.uk>.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

=cut

