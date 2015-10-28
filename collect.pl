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

use Data::Dumper;
use Thread;
use Thread::Queue;
use Term::ANSIColor;

use Pod::Usage;
use Getopt::Long;
use JSON -support_by_pp;
use Net::DNS;
use Net::DNS::SEC;

# global program parameters
my $config = 'collect.json';
my $DEBUG  = 0; # set to true if you want some debug output
my $pretty = 0; # set to true to output pretty JSON
my $threads = 80; # default number of threads
my $outdir;
my $filename;

my $par = 0; # think of the parenthesis
my $rr = ""; # global rr var

my $queue = Thread::Queue->new();

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

# global resolver
my $res = Net::DNS::Resolver->new;
$res->nameservers($c->{'resolver'});
$res->recurse(1);
$res->dnssec(1);
$res->cdflag(0);
$res->udppacketsize(4096);
$res->tcp_timeout(10);
$res->udp_timeout(10);

# parent server for all delegations (ie a.ns.se for .se domains)
# (we could also use a non-validating recursive resolver)
my $fnsse = Net::DNS::Resolver->new;
$fnsse->nameservers(@parents);
$fnsse->recurse(0);
$fnsse->dnssec(1);
$fnsse->cdflag(0);
$fnsse->udppacketsize(4096);
$fnsse->tcp_timeout(5);
$fnsse->udp_timeout(5);


# fetch all data we need for a domain name, returns with a hash
sub readDNS
{
    my $name = shift;

    my $count; # retry counter

    my $result; # resulting JSON stuffz
    $result->{'domain'} = $name;
    my $answer; # for DNS answers

    print "Quering DS for $name\n" if $DEBUG;
    $count = 0;
    while (1) {
	$count++;
	last if $count > 5;
	$answer = $res->query($name,'DS');
	next if not defined $answer;
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
	last;
    }

    print "Quering DNSKEY for $name\n" if $DEBUG;
    $count = 0;
    while (1) {
	$count++;
	if ($count > 5) { $result->{'dnskey'}->{'rcode'} = 'TIMEOUT'; last; }
	$answer = $res->send($name,'DNSKEY');
	next if not defined $answer;
	$result->{'dnskey'}->{'rcode'} = $answer->header->rcode;
	if ($result->{'dnskey'}->{'rcode'} eq '') { print "FOO: $name\n"; next; }
	foreach my $data ($answer->answer)
	{
	    if ($data->type eq 'DNSKEY') {
		push @{$result->{'dnskey'}->{'list'}}, {
		    'algorithm' => $data->algorithm,
		    'keylength' => $data->keylength,
		    'is_sep'    => $data->sep,
                    'keytag'    => $data->keytag,
                    'key'       => $data->key,
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
	last;
    }

    print "Quering NSEC3PARAM for $name\n" if $DEBUG;
    $count = 0;
    while (1) {
	$count ++;
	if ($count > 5) { $result->{'nsec3param'}->{'rcode'} = 'TIMEOUT'; last; }
	$answer = $res->send($name,'NSEC3PARAM');
	next if not defined $answer;
	$result->{'nsec3param'}->{'rcode'} = $answer->header->rcode;
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
	last;
    }

    print "Quering SOA for $name\n" if $DEBUG;
    $count = 0;
    while (1) {
	$count++;
	if ($count > 5) { $result->{'soa'}->{'rcode'} = 'TIMEOUT'; last; }
	$answer = $res->send($name,'SOA');
	next if not defined $answer;
	$result->{'soa'}->{'rcode'} = $answer->header->rcode;
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
	last;
    }

    print "Quering A for www.$name\n" if $DEBUG;
    $count = 0;
    while (1) {
	$count++;
	if ($count > 5) { $result->{'A'}->{'rcode'} = 'TIMEOUT'; last; }
	$answer = $res->send($name,'A');
	next if not defined $answer;
	$result->{'A'}->{'rcode'} = $answer->header->rcode;
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
	last;
    }

    print "Quering MX for $name\n" if $DEBUG;
    $count = 0;
    while (1) {
	$count++;
	if ($count > 5) { $result->{'MX'}->{'rcode'} = 'TIMEOUT'; last; }
	$answer = $res->send($name,'MX');
	next if not defined $answer;
	$result->{'MX'}->{'rcode'} = $answer->header->rcode;
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
	last;
    }

    print "Quering ns for $name\n" if $DEBUG;
    $count = 0;
    while (1) {
	$count++;
	if ($count > 5) { $result->{'NS'}->{'rcode'} = 'TIMEOUT'; last; }
	$answer = $fnsse->send($name,'NS');
	next if not defined $answer;
	$result->{'NS'}->{'rcode'} = $answer->header->rcode;
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
	last;
    }

    return $result;
}

# find values in a hash by adressing it like this "key:key2:key3"
sub findValue {
    my $hash = shift;
    my $find = shift;
    my $value;
    my $defined;
    my @keys = split (':',$find);
    @keys = map { "{'$_'}" } @keys;
    my $evalHash = '$hash->'.join('->',@keys);
    eval '$defined = defined '.$evalHash;
    return undef if $@;
    return undef if $defined eq '';
    eval '$value = '.$evalHash;
    return undef if $@;
    return $value if defined $value;
    return 1;
}

sub processDomain {
    while (defined(my $domain = $queue->dequeue_nb)) {
	chomp $domain;
	my $res = readDNS($domain);
	print color 'reset';
	if(findValue($res,'A:rcode')          eq 'SERVFAIL' or
	   findValue($res,'MX:rcode')         eq 'SERVFAIL' or
	   findValue($res,'soa:rcode')        eq 'SERVFAIL' or
	   findValue($res,'nsec3param:rcode') eq 'SERVFAIL' or
	   findValue($res,'dnskey:rcode')     eq 'SERVFAIL') {
	   print"$domain: "; print color 'red'; print "SERVFAIL\n"; print color 'reset';
	} else {
	   print"$domain: "; print color 'green'; print "OK\n"; print color 'reset';
	}
	# output result
	open(OUT, '>', "$outdir/$domain") or die $!;
	print OUT to_json($res, { utf8 => 1 });
	close(OUT);
    }
    threads->exit();
}

sub runQueue {
    die "cannot create directory $outdir: $!" if not mkdir $outdir;
    die 'no file for runQueue()'              if not defined $filename;
    die 'no outdir for runQueue()'            if not defined $outdir;

    open FILE, "$filename" or die "Cannot read file $filename: $!";
    while ( <FILE> ) {
	$queue->enqueue($_);
    }
    close FILE;

    threads->create({'stack_size' => 32*4096}, "processDomain") for (1 .. $threads);

    while(threads->list(threads::running) != 0) {
	print color 'yellow'; 
	print "Pending: ".$queue->pending()." - Running: ".threads->list(threads::running)."\n";
	print color 'reset';
	sleep(2);
    }

}

sub main() {
    # non-global program parameters
    my $help = 0;
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
    -d outdir       create this directory and store result in if reading domains from file
    --threads       number of threads
    --debug         debug mode
    --pretty        print in pretty mode

=head1 DESCRIPTION

   gets DNSSEC data for domain (outputs JSON)

=head1 AUTHOR

   Patrik Wallstrom <pawal@iis.se>

=cut
