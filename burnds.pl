#!/usr/bin/perl

use warnings;
use strict;

use Pod::Usage;
use Getopt::Long;
use JSON -support_by_pp;
use Net::DNS;
use Net::DNS::SEC;

use Data::Dumper;

# program params
my $DEBUG  = 0; # set to true if you want some debug output
my $pretty = 0; # set to true to output pretty JSON
my $name;

my $maxlines = 50000; # max number of lines to read for example...
my $i = 0;   # line counter

my $par = 0; # think of the parenthesis
my $rr = ""; # global rr var

# global resolver
my $res = Net::DNS::Resolver->new;
$res->nameservers('212.247.18.10');
$res->recurse(1);
$res->dnssec(1);
$res->cdflag(0);
$res->udppacketsize(4096);

# read and parse the zonefile, building a hash with the data we want
sub readDNS
{
    my $name = shift;
    # resolve name DS
    # resolve name DNSKEY
    # resolve name NSEC3PARAM

    my $result; # resulting JSON stuffz
    $result->{'domain'} = $name;

    print "Quering DS for $name\n" if $DEBUG;
    my $answer = $res->query($name,'DS');
    if (defined $answer) {
	foreach my $data ($answer->answer)
	{
	    if ($data->type eq 'DS') {
		push @{$result->{'ds'}}, {
		    'digest'    => $data->digest,
		    'digtype'   => $data->digtype,
		    'algorithm' => $data->algorithm,
		};
		print "DS $name: ".$data->digest."\n" if $DEBUG;
		print "DS $name: ".$data->digtype."\n" if $DEBUG;
	    }
	}
    }

    print "Quering DNSKEY for $name\n" if $DEBUG;
    $answer = $res->send($name,'DNSKEY');
    $result->{'dnskey'}->{'rcode'} = $answer->header->rcode;
    if (defined $answer) {
	foreach my $data ($answer->answer)
	{
	    if ($data->type eq 'DNSKEY') {
		push @{$result->{'dnskey'}->{'list'}}, {
		    'algorithm' => $data->algorithm,
		    'keylength' => $data->keylength,
		    'is_sep'    => $data->is_sep,
		};
		print "DNSKEY $name: ".$data->key."\n" if $DEBUG;
	    } elsif ($data->type eq 'RRSIG') {
		push @{$result->{'rrsig'}}, {
		    'siginception'  => $data->siginception,
		    'sigexpiration' => $data->sigexpiration,
		    'typecovered'   => $data->typecovered,
		    'algorithm'     => $data->algorithm,
		};
		print "RRSIG $name: ".$data->keytag."\n" if $DEBUG;
	    }
	    $i++;
	}
    }

    print "Quering NSEC3PARAM for $name\n" if $DEBUG;
    $answer = $res->send($name,'NSEC3PARAM');
    $result->{'nsec3param'}->{'rcode'} = $answer->header->rcode;
    if (defined $answer) {
	foreach my $data ($answer->answer)
	{
	    if ($data->type eq 'NSEC3PARAM') {
		$result->{'nsec3param'}->{'hashalgo'}   = $data->hashalgo;
		$result->{'nsec3param'}->{'flags'}      = $data->flags;
		$result->{'nsec3param'}->{'iterations'} = $data->iterations;
		$result->{'nsec3param'}->{'salt'}       = $data->salt;
		print "NSEC3PARAM $name: ".$data->iterations."\n" if $DEBUG;
	    } elsif ($data->type eq 'RRSIG') {
		push @{$result->{'rrsig'}}, {
		    'siginception'  => $data->siginception,
		    'sigexpiration' => $data->sigexpiration,
		    'typecovered'   => $data->typecovered,
		    'algorithm'     => $data->algorithm,
		};
		print "RRSIG $name: ".$data->keytag."\n" if $DEBUG;
	    }
	}
    }

    print "Quering SOA for $name\n" if $DEBUG;
    $answer = $res->send($name,'SOA');
    $result->{'soa'}->{'rcode'} = $answer->header->rcode;
    if (defined $answer) {
	foreach my $data ($answer->answer)
	{
	    if ($data->type eq 'SOA') {
		$result->{'soa'}->{'mname'}   = $data->mname;
		$result->{'soa'}->{'rname'}   = $data->rname;
		$result->{'soa'}->{'serial'}  = $data->serial;
		$result->{'soa'}->{'refresh'} = $data->refresh;
		$result->{'soa'}->{'retry'}   = $data->retry;
		$result->{'soa'}->{'expire'}  = $data->expire;
		$result->{'soa'}->{'minimum'} = $data->minimum;
		print "SOA $name: ".$data->iterations."\n" if $DEBUG;
	    } elsif ($data->type eq 'RRSIG') {
		push @{$result->{'rrsig'}}, {
		    'siginception'  => $data->siginception,
		    'sigexpiration' => $data->sigexpiration,
		    'typecovered'   => $data->typecovered,
		    'algorithm'     => $data->algorithm,
		};
		print "RRSIG $name: ".$data->keytag."\n" if $DEBUG;
	    }
	}
    }

    print "Quering A for www.$name\n" if $DEBUG;
    $answer = $res->send($name,'A');
    $result->{'A'}->{'rcode'} = $answer->header->rcode;
    if (defined $answer) {
	foreach my $data ($answer->answer)
	{
	    if ($data->type eq 'A') {
		push @{$result->{'A'}->{'list'}}, {
		    'address' => $data->address,
		};
		print "A www.$name: ".$data->address."\n" if $DEBUG;
	    } elsif ($data->type eq 'RRSIG') {
		push @{$result->{'rrsig'}}, {
		    'siginception'  => $data->siginception,
		    'sigexpiration' => $data->sigexpiration,
		    'typecovered'   => $data->typecovered,
		    'algorithm'     => $data->algorithm,
		};
		print "RRSIG www.$name: ".$data->keytag."\n" if $DEBUG;
	    }
	}
    }

    print "Quering MX for $name\n" if $DEBUG;
    $answer = $res->send($name,'MX');
    $result->{'MX'}->{'rcode'} = $answer->header->rcode;
    if (defined $answer) {
	foreach my $data ($answer->answer)
	{
	    if ($data->type eq 'MX') {
		push @{$result->{'MX'}->{'list'}}, {
		    'exchange'   => $data->exchange,
		    'preference' => $data->preference,
		};
		print "MX $name: ".$data->exchange."\n" if $DEBUG;
	    } elsif ($data->type eq 'RRSIG') {
		push @{$result->{'rrsig'}}, {
		    'siginception'  => $data->siginception,
		    'sigexpiration' => $data->sigexpiration,
		    'typecovered'   => $data->typecovered,
		    'algorithm'     => $data->algorithm,
		};
		print "RRSIG www.$name: ".$data->keytag."\n" if $DEBUG;
	    }
	}
    }

    return $result;
}

# lets fetch all keys and params from the child zones
sub fetchKeys
{
    my $dnsData = shift;
    my @ds;
    my @keys;
    my @rrsig;

    print " -=> Fetching stuff from DNS <=-\n" if $DEBUG;

    foreach my $domain (keys %$dnsData)
    {
	next if not exists $dnsData->{$domain}->{'DS'};

	# DNSKEY query
	print "Quering DNSKEY for $domain\n" if $DEBUG;
	my $answer = $res->query($domain,'DNSKEY');
	if (defined $answer) {
	    my $i = 0; # temp counter
	    foreach my $data ($answer->answer)
	    {
		if ($data->type eq 'DNSKEY') {
		    push @keys, $data;
		    $dnsData->{$domain}->{'DNSKEY'}->{$i}->{'RR'} = $data;
		    print "DNSKEY $domain: ".$data->keytag."\n" if $DEBUG;
		}
		if ($data->type eq 'RRSIG') {
		    push @rrsig, $data;
		    $dnsData->{$domain}->{'RRSIG'}->{$i}->{'RR'} = $data;
		    print "RRSIG $domain: ".$data->keytag."\n" if $DEBUG;
		}
		$i++;
	    }
	}

	# NSEC3PARAM query
	print "Quering NSEC3PARAM for $domain\n" if $DEBUG;
	$answer = $res->query($domain,'NSEC3PARAM');
	if (defined $answer) {
	    foreach my $data ($answer->answer)
	    {
		if ($data->type eq 'NSEC3PARAM') {
		    print "NSEC3PARAM: ".$data->string."\n";
		    $dnsData->{$domain}->{'NSEC3PARAM'} = $data;
		}
	    }
	}
    }
}

sub main() {
    my $help = 0;
    GetOptions('help|?'   => \$help,
	       'name|n=s' => \$name,
	       'debug'    => \$DEBUG,
	       'pretty'   => \$pretty,)
    or pod2usage(2);
    pod2usage(1) if($help);
    pod2usage(1) if(not defined $name);

    my $dnsData = readDNS($name);
    print to_json($dnsData, { utf8 => 1, pretty => $pretty} );
}

main;

=head1 NAME

burnds

=head1 SYNOPSIS

   burnds.pl -n domain

    -n domain       specify name
    --debug         debug mode
    --pretty        print in pretty mode
=head1 DESCRIPTION

   gets DNSSEC data for domain (outputs JSON)

=head1 AUTHOR

   Patrik Wallstrom <pawal@iis.se>

=cut
