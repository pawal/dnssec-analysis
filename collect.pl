#!/usr/bin/perl

# Copyright (c) 2012 The Internet Infrastructure Foundation (.SE). All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use warnings;
use strict;

use Thread;
use Thread::Queue;

use Pod::Usage;
use Getopt::Long;
use JSON -support_by_pp;
use Net::DNS;
use Net::DNS::SEC;

# program parameters
my $config = 'collect.json';
my $DEBUG  = 0; # set to true if you want some debug output
my $pretty = 0; # set to true to output pretty JSON
my $threads = 20; # default number of threads

my $par = 0; # think of the parenthesis
my $rr = ""; # global rr var

# read configuration file for at least the resolver
open CONFIG, "$config" or warn "Cannot read config file $config";
my @CONFIG = <CONFIG>;
close CONFIG;
my $CONF = join '',@CONFIG;
my $c = from_json($CONF);

# set up params from config file
$threads = $c->{'threads'} if defined $c->{'threads'};
my $local_resolver = $c->{'resolver'};
my @parents = @{$c->{'parents'}};

# read and parse the zonefile, building a hash with the data we want
sub readDNS
{
    my $name = shift;

    # global resolver
    my $res = Net::DNS::Resolver->new;
    $res->nameservers($c->{'resolver'});
    $res->recurse(1);
    $res->dnssec(1);
    $res->cdflag(0);
    $res->udppacketsize(4096);

    # parent server for all delegations (ie a.ns.se for .se domains)
    # (we could also use a non-validating recursive resolver)
    my $fnsse = Net::DNS::Resolver->new;
    $fnsse->nameservers(@parents);
    $fnsse->recurse(0);
    $fnsse->dnssec(1);
    $fnsse->cdflag(0);
    $fnsse->udppacketsize(4096);

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

    print "Quering ns for www.$name\n" if $DEBUG;
    $answer = $fnsse->send($name,'NS');
    $result->{'NS'}->{'rcode'} = $answer->header->rcode;
    if (defined $answer) {
	foreach my $data ($answer->authority)
	{
	    if ($data->type eq 'NS') {
		push @{$result->{'NS'}->{'list'}}, {
		    'nsdname' => $data->nsdname,
		};
		print "NS $name: ".$data->nsdname."\n" if $DEBUG;
	    } elsif ($data->type eq 'RRSIG') {
		push @{$result->{'rrsig'}}, {
		    'siginception'  => $data->siginception,
		    'sigexpiration' => $data->sigexpiration,
		    'typecovered'   => $data->typecovered,
		    'algorithm'     => $data->algorithm,
		};
	    }
	}
    }

    return $result;
}

sub runQueue {
    my $file = shift||die 'no file for runQueue()';
    my $outdir = shift||die 'no outdir for runQueue()';
}

sub main() {
    # non-global program parameters
    my $help = 0;
    my $outdir;
    my $filename;
    my $name;
    GetOptions('help|?'     => \$help,
	       'name|n=s'   => \$name,
	       'file|f=s'   => \$filename,
	       'outdir|d=s' => \$outdir,
	       'threads'    => \$threads,
	       'debug'      => \$DEBUG,
	       'pretty'     => \$pretty,)
    or pod2usage(2);
    pod2usage(1) if($help);
    pod2usage(1) if(not defined $name and not defined $filename);

    if (defined $name) {
	my $dnsData = readDNS($name);
	print to_json($dnsData, { utf8 => 1, pretty => $pretty} );
    } elsif (defined $filename) {
	runQueue($filename,$outdir);
    }
}

main;

=head1 NAME

collect

=head1 SYNOPSIS

   collect.pl -n domain

    -n domain       specify name
    -f file.txt     read list of names from file
    --threads       number of threads
    --debug         debug mode
    --pretty        print in pretty mode
=head1 DESCRIPTION

   gets DNSSEC data for domain (outputs JSON)

=head1 AUTHOR

   Patrik Wallstrom <pawal@iis.se>

=cut
