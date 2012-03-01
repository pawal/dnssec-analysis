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

use JSON;                        # for input and output of data files
use Data::Dumper;                # debugging
use Encode qw< encode decode >;  # UTF-8 stuff
use List::Util qw[min max sum];  # for finding min and max values in lists
use Data::Serializer;            # for serializing data (needs work)
use Getopt::Long;                # option handling
use DateTime::Format::Strptime;  # converting RRSIG times
use Pod::Usage;                  # documentation

### OPTIONS
my $analyzeRcode;
my $analyzeServfail;
my $analyzeServfailList;
my $analyzeWorkingNS;
my $analyzeSigLife;
my $analyzeExtremeSigs;
my $analyzeAlgorithms;
my $anaLyzeNSEC3;
my $analyzeExpiration;
my $analyzeDSDuplicates;
my $recache = 0;
my $directory;
my $fakedate;
my $limit = 0;

# get command line options
GetOptions(
    'help|?'         => \$help,
    'directory|d=s'  => \$directory,
    'limit|l=i'      => \$limit,
    'recache'        => \$recache,
    'fakedate=s'     => \$fakedate,
    'rcode'          => \$analyzeRcode,
    'servfail'       => \$analyzeServfail,
    'servfaillist=s' => \$analyzeServfailList,
    'dsduplicates'   => \$analyzeDSDuplicates,
    'working-ns'     => \$analyzeWorkingNS,
    'siglife'        => \$analyzeSigLife,
    'extreme-sigs'   => \$analyzeExtremeSigs,
    'expiration'     => \$analyzeExpiration,
    'algorithms'     => \$analyzeAlgorithms,
    'nsec3'          => \$analyzeNSEC3,
    'verbose|v+'     => \$verbose,
    ) or pod2usage(2);

# help command line option
if ($help or not defined $directory) {
    pod2usage(1);
    exit;
}

main();
exit;

sub delimiter {
    print "----------------------\n";
}

# see if we have this data serialized already
sub checkSerializer
{
    my $file = shift || die 'No file given to checkSerializer';

    if (-e "$directory/$file") {
	print "De-serializing data\n";
	my $serialize = Data::Serializer->new();
	my $obj = $serialize->retrieve("$directory/$file");
	return $obj;
    }
    return undef;
}

# store serialized data, for cacheing purposes
sub createSerialize
{
    my $obj = shift;
    my $file = shift;  
    my $serialize = Data::Serializer->new(serializer => 'JSON');
    $serialize->store($obj,"$directory/$file");
    print "Serialization done\n";
}

sub main {
    # get all entries from the domain directory

    #my %super; # all json stuff in one giant hash
    my $alldata; # all json stuff in one giant hash
    my $cachefile = 'serialize.txt';

    $alldata = checkSerializer($cachefile);
    if (not defined $alldata) {
	print "Reading all json files...\n";
	opendir DIR,"$directory/" or die "Cannot open directory: $!";
	my @all = grep { -f "$directory/$_" } readdir(DIR);
	closedir DIR;

	foreach my $file (@all) {
	    # if ((stat($filename))[7] == 0) { next; };
	    open FILE, "$directory/$file" or die "Cannot read file domain/$file: $!";
	    my @j = <FILE>;
	    next if not defined $j[0];
	    $j = getJSON($j[0]);
	    $alldata->{$j->{'domain'}} = $j if defined $j;
	    close FILE;
	}
    }
    createSerialize($alldata,'serialize.txt');
    print "Running analysis\n";

    if ($analyzeRcode) {
	print "Return codes:\n";
	analyzeRcodes($alldata);
	delimiter;
    }
    if ($analyzeServfail) {
	print "Toplist of name servers with SERVFAIL:\n";
	analyzeServfails($alldata);
	delimiter;
    }
    if ($analyzeServfailList) {
	print "List of SERVFAIL domains for $analyzeServfailList:\n";
	getServfailList($alldata,$analyzeServfailList);
	delimiter;
    }
    if ($analyzeDSDuplicates) {
	print "Number of domains that has the same DS records:\n";
	analyzeDSDuplicates($alldata);
	delimiter;
    }
    if ($analyzeWorkingNS) {
	print "Toplist of name servers with NO ERROR on all queries\n";
	analyzeWorkingNS($alldata);
	delimiter;
    }
    if ($analyzeSigLife) {
	print "Analysis of RRSIG lifetimes:\n";
	analyzeSigLifetimes($alldata,$fakedate);
	delimiter;
    }
    if ($analyzeExtremeSigs) {
	print "List extreme RRSIG lifetimes (inception and expiration larger than 100 days):\n";
	extremeSigLifetimes($alldata,$fakedate);
	delimiter;
    }
    if ($analyzeExpiration) {
	print "Number of days that SOA expire is larger then lowest RRSIG (expire-rrsig, count):\n";
	analyzeExpiration($alldata,$fakedate);
	delimiter;
    }
    if ($analyzeAlgorithms) {
	print "DNSSEC Algorithms:\n";
	analyzeAlgorithms($alldata);
	delimiter;
    }
    if ($analyzeNSEC3) {
	print "NSEC3 Analysis:\n";
	analyzeNSEC3($alldata);
	delimiter;
    }

    print "Domains with data: ".scalar keys(%{$alldata})."\n";
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

sub getJSON {
    # fix utf-8 problems and decode JSON
    my $j = shift;
    $j = encode('UTF-8', $j);
    $j = JSON->new->utf8->decode($j);
    return $j;
}

# analyze domain
sub analyzeRcodes {
    my $bighash = shift;
    my %result;

    # collect data
    foreach my $domain (keys(%{$bighash})) {
	$result{'A:'.findValue($bighash->{$domain},          'A:rcode')}++;
	$result{'MX:'.findValue($bighash->{$domain},         'MX:rcode')}++;
	$result{'SOA:'.findValue($bighash->{$domain},        'soa:rcode')}++;
	$result{'NSEC3PARAM:'.findValue($bighash->{$domain}, 'nsec3param:rcode')}++;
	$result{'DNSKEY:'.findValue($bighash->{$domain},     'dnskey:rcode')}++;
    }

    # output summary
    foreach my $key (sort keys(%result)) {
	print "$key: $result{$key}\n";
    }
}

# list of total servfails
sub analyzeServfails {
    my $bighash = shift;
    my %result;
    my $count = 0;;

    # collect data
    foreach my $domain (keys(%{$bighash})) {
	if(findValue($bighash->{$domain},'A:rcode') eq 'SERVFAIL' or
	   findValue($bighash->{$domain},'MX:rcode') eq 'SERVFAIL' or
	   findValue($bighash->{$domain},'soa:rcode') eq 'SERVFAIL' or
	   findValue($bighash->{$domain},'nsec3param:rcode') eq 'SERVFAIL' or
	   findValue($bighash->{$domain},'dnskey:rcode') eq 'SERVFAIL') {
	    foreach my $rrs (findValue($bighash->{$domain},'NS:list')) {
		foreach my $ns (@$rrs) {
		    $result{$ns->{'nsdname'}}++;
		}
	    }
	    $count++;
	}
    }

    # output summary
    my $i = 0;
    foreach my $key (sort { $result{$b} <=> $result{$a} } keys %result) {
	print "$key: $result{$key}\n";
	$i++;
	last if $i > $limit and $limit > 0;
    }
    print "Total number of domains with any SERVFAIL: $count\n";
}

sub getServfailList {
    my $bighash = shift;
    my $nameserver = shift;
    my @result;

    # collect data
    foreach my $domain (keys(%{$bighash})) {
	if(findValue($bighash->{$domain},'A:rcode') eq 'SERVFAIL' or
	   findValue($bighash->{$domain},'MX:rcode') eq 'SERVFAIL' or
	   findValue($bighash->{$domain},'soa:rcode') eq 'SERVFAIL' or
	   findValue($bighash->{$domain},'nsec3param:rcode') eq 'SERVFAIL' or
	   findValue($bighash->{$domain},'dnskey:rcode') eq 'SERVFAIL') {
	    foreach my $rrs (findValue($bighash->{$domain},'NS:list')) {
		foreach my $ns (@$rrs) {
		    if ($ns->{'nsdname'} eq $nameserver) {
			push @result, $domain;
		    }
		}
	    }
	}
    }

    # output list of domains
    foreach my $domain (sort @result) {
	print "SERVFAIL $nameserver: $domain\n";
    }
}

# find all DS duplicates among domains and output
sub analyzeDSDuplicates {
    my $bighash = shift;
    my $nameserver = shift;
    my %result;

    # collect data
    foreach my $domain (keys(%{$bighash})) {
	my $dss = $bighash->{$domain}->{'ds'};
	foreach my $ds (@$dss) {
	    $result{$ds->{'digest'}}++;
	}
    }

    # output summary
    my $i = 0;
    foreach my $key (sort { $result{$b} <=> $result{$a} } keys %result) {
	print "$key: $result{$key}\n";
	$i++;
	last if $i > $limit and $limit > 0;
    }
}

# list of all NS with NOERROR
sub analyzeWorkingNS {
    my $bighash = shift;
    my %result;

    # collect data
    foreach my $domain (keys(%{$bighash})) {
	if(findValue($bighash->{$domain},'A:rcode') eq 'NOERROR' and
	   findValue($bighash->{$domain},'MX:rcode') eq 'NOERROR' and
	   findValue($bighash->{$domain},'soa:rcode') eq 'NOERROR' and
	   findValue($bighash->{$domain},'nsec3param:rcode') eq 'NOERROR' and
	   findValue($bighash->{$domain},'dnskey:rcode') eq 'NOERROR') {
	    foreach my $rrs (findValue($bighash->{$domain},'NS:list')) {
		foreach my $ns (@$rrs) {
		    $result{$ns->{'nsdname'}}++;
		}
	    }
	}
    }

    # output summary
    my $i = 0;
    foreach my $key (sort { $result{$b} <=> $result{$a} } keys %result) {
	print "$key: $result{$key}\n";
	$i++;
	last if $i > $limit and $limit > 0;
    }
}

# create a fake date and return a DateTime-object (for date comparisons)
sub getFakeDate {
    my $fakedate = shift;
    my $strp = new DateTime::Format::Strptime(
	pattern   => '%Y-%m-%d',
	time_zone => 'UTC',
	on_error  => 'croak');
    if (defined $fakedate) {
	my $ft = $strp->parse_datetime($fakedate);
	return $ft;
    }
    return undef;
}

# analyze DNSKEY, DS and RRSIG Algorithms
sub analyzeAlgorithms {
    my $bighash = shift;
    my (%rrsig, %ds, %dnskey, %ksk, %zsk, %dnskeylen, %ksklen, %zsklen);
    my $i = 0;

    # collect data (build result hashes)
    foreach my $domain (keys(%{$bighash})) {
	next if $bighash->{$domain}->{'dnskey'}->{'rcode'} eq 'SERVFAIL';
	my $dss     = findValue($bighash->{$domain},'ds');
	my $rrsigs  = findValue($bighash->{$domain},'rrsig');
	my $dnskeys = findValue($bighash->{$domain},'dnskey:list');

	# DS records
	map { $ds{$_->{'digtype'}}++ }       @$dss;
	# RRSIG algorithms, skip DS since not from child zone
	map { $rrsig{$_->{'algorithm'}}++ } grep ($_->{'typecovered'} ne 'DS', @$rrsigs);
	# DNSKEY keylengths and algorithms
	foreach my $key (@$dnskeys) {
	    $dnskey{$key->{'algorithm'}}++;
	    $dnskeylen{$key->{'keylength'}}++;
	    if ($key->{'is_sep'}) {
		$ksk{$key->{'algorithm'}}++;
		$ksklen{$key->{'keylength'}}++;
	    } else {
		$zsk{$key->{'algorithm'}}++;
		$zsklen{$key->{'keylength'}}++;
	    }		
	}
	$i++; # count working zones
    }

    # collect totals
    my $total = int grep $bighash{$_}->{'dnskey'}->{'rcode'} ne 'NOERROR', keys(%{$bighash});
    my $dstotal     = 0; ($dstotal     += $_) for values %ds;
    my $dnskeytotal = 0; ($dnskeytotal += $_) for values %dnskey;
    my $ksktotal    = 0; ($ksktotal    += $_) for values %ksk;
    my $zsktotal    = 0; ($zsktotal    += $_) for values %zsk;

    # output summary
    map { print "DS Digest type    $_: $ds{$_}\n"; }        sort {$a <=> $b} keys %ds;
    map { print "RRSIG Algorithms  $_: $rrsig{$_}\n"; }     sort {$a <=> $b} keys %rrsig;
    map { print "DNSKEY Algorithms $_: $dnskey{$_}\n"; }    sort {$a <=> $b} keys %dnskey;
    map { print "DNSKEY Keylengths $_: $dnskeylen{$_}\n"; } sort {$a <=> $b} keys %dnskeylen;
    map { print " (KSK) Algorithms $_: $ksk{$_}\n"; }       sort {$a <=> $b} keys %ksk;
    map { print " (ZSK) Algorithms $_: $zsk{$_}\n"; }       sort {$a <=> $b} keys %zsk;
    map { print " (KSK) Keylengths $_: $ksklen{$_}\n"; }    sort {$a <=> $b} keys %ksklen;
    map { print " (ZSK) Keylengths $_: $zsklen{$_}\n"; }    sort {$a <=> $b} keys %zsklen;
    print "Total DS:     $dstotal\n";
    print "Total KSK:    $ksktotal\n";
    print "Total ZSK:    $zsktotal\n";
    print "Total DNSKEY: $dnskeytotal\n";
    print "DS per domain:     ".$dstotal / $i."\n";
    print "KSK per domain:    ".$ksktotal / $i."\n";
    print "ZSK per domain:    ".$zsktotal / $i."\n";
    print "DNSKEY per domain: ".$dnskeytotal / $i."\n";
    print "Algorithms based on total $i zones - the rest was SERVFAIL\n";
}

# analyze NSEC3 (salt, iterations)
sub analyzeNSEC3 {
    my $bighash = shift;
    my (%saltlen, %iterations, %hashalgo);
    my $i = 0;
    my $nsec3tot = 0;

    # collect data (build result hashes)
    foreach my $domain (keys(%{$bighash})) {
	next if $bighash->{$domain}->{'dnskey'}->{'rcode'} eq 'SERVFAIL';
	$i++; # count working zones
	my $nsec3param = findValue($bighash->{$domain},'nsec3param');
	next if not defined $nsec3param->{'hashalgo'};
	$nsec3tot++; # this is nsec3
	$saltlen{length($nsec3param->{'salt'})}++;
	$iterations{$nsec3param->{'iterations'}}++;
	$hashalgo{$nsec3param->{'hashalgo'}}++;
    }

    # collect totals
    my $nsectot = $i - $nsec3tot;

    # output summary
    map { print "NSEC3 Salt length $_: $saltlen{$_}\n"; } sort {$a <=> $b} keys %saltlen;
    map { print "NSEC3 Iterations $_: $iterations{$_}\n"; } sort {$a <=> $b} keys %iterations;
    map { print "NSEC3 Hash algorithm $_: $hashalgo{$_}\n"; } sort {$a <=> $b} keys %hashalgo;
    print "NSEC zones: $nsectot\n";
    print "NSEC analysis based on total $i zones - the rest was SERVFAIL\n";
}

# finds extreme lifetimes where extreme is hardcoded to 100 days diff from expiration or inception
sub extremeSigLifetimes {
    my $bighash = shift;

    my $fakedate = shift;
    my $strp = new DateTime::Format::Strptime(
	pattern   => '%Y%m%d%H%M%S',
	time_zone => 'UTC');
    $fakedate = getFakeDate($fakedate) if defined $fakedate;
    my $now = defined $fakedate ? $fakedate : DateTime->now; # now is possibly another date
    my @extremes;

    # collect data
    foreach my $domain (keys(%{$bighash})) {
	my $rrsigarray = findValue($bighash->{$domain},'rrsig');
	my (@inc,@exp,@tot);
	foreach my $rrsig (@$rrsigarray) {
	    next if $rrsig->{'typecovered'} eq 'DS'; # skip DS, not from child zone
	    my $sigexp = $strp->parse_datetime($rrsig->{'sigexpiration'});
	    my $siginc = $strp->parse_datetime($rrsig->{'siginception'});
	    my $inc = int $siginc->subtract_datetime_absolute($now)->delta_seconds / 86400;
	    my $exp = int $sigexp->subtract_datetime_absolute($now)->delta_seconds / 86400;
	    if ($inc < -100 or $exp > 100) {
		push @extremes,$domain;
		last;
	    }
	}
    }

    # output summary
    foreach (@extremes) { print "$_\n"; }
}

# discover the validity lifetimes of the signatures
sub analyzeSigLifetimes {
    my $bighash = shift;
    my $fakedate = shift;
    my $now;

    my %exps; # expiration times in days
    my %incs; # inception times in days
    my %life; # difference between expiration and inception in days

    my $res;  # new result hash

    # convert RRSIG times to DateTime objects with $strp
    my $strp = new DateTime::Format::Strptime(
	pattern   => '%Y%m%d%H%M%S',
	time_zone => 'UTC');
    $fakedate = getFakeDate($fakedate) if defined $fakedate;
    $now = defined $fakedate ? $fakedate : DateTime->now; # now is possibly another date

    # collect data
    my $i = 0; # temp limit
    foreach my $domain (keys(%{$bighash})) {
	my $rrsigarray = findValue($bighash->{$domain},'rrsig');
	my (@inc,@exp,@tot);
	my $sigcount = 0;
	foreach my $rrsig (@$rrsigarray) {
	    next if $rrsig->{'typecovered'} eq 'DS'; # skip DS, not from child zone
	    my $sigexp = $strp->parse_datetime($rrsig->{'sigexpiration'});
	    my $siginc = $strp->parse_datetime($rrsig->{'siginception'});
	    my $inc = int $siginc->subtract_datetime_absolute($now)->delta_seconds / 86400;
	    my $exp = int $sigexp->subtract_datetime_absolute($now)->delta_seconds / 86400;
	    my $tot = int $sigexp->subtract_datetime_absolute($siginc)->delta_seconds / 86400;
	    $incs{$inc}++; # build result hash with inception times
	    $exps{$exp}++; # build result hash with expiration times
	    $life{$tot}++; # build result hash with total lifetimes
	    push @inc, $inc;
	    push @exp, $exp;
	    push @tot, $tot;
	    $sigcount++;
	}
	next if $sigcount == 0;

	# calc and store results
	$res->{'incmin'}->{min @inc}++;
	$res->{'incmax'}->{max @inc}++;
	$res->{'incavg'}->{sprintf('%.0f',(sum @inc)/$sigcount)}++;
	$res->{'expmin'}->{min @exp}++;
	$res->{'expmax'}->{max @exp}++;
	$res->{'expavg'}->{sprintf('%.0f',(sum @exp)/$sigcount)}++;

	$i++;
	last if $i > $limit and $limit > 0;
    }

    # output data

    # use closure to print all these hashes with results
    my $loop = sub {
	my $var = shift;
	foreach my $days (sort {$a <=> $b} keys %{$res->{$var}}) {
	    print "$days,".$res->{$var}->{$days}."\n";
	}
    };

    print "Signature average inception (days, count)\n";
    &$loop('incavg');
    delimiter;
    print "Signature lowest inception (days, count)\n";
    &$loop('incmin');
    delimiter;
    print "Signature highest inception (days, count)\n";
    &$loop('incmax');
    delimiter;
    print "Signature average expiration (days, count)\n";
    &$loop('expavg');
    delimiter;
    print "Signature lowest expiration (days, count)\n";
    &$loop('expmin');
    delimiter;
    print "Signature highest expiration (days, count)\n";
    &$loop('expmax');
}

# Correlate SOA expiration value with lowest RRSIG lifetime
sub analyzeExpiration {
    my $bighash = shift;
    my $fakedate = shift;
    my $now;
    my ($lower, $higher) = (0,0,0);

    my %res; # result hash
    my %soaexpire; # results for the SOA expire
    my $notdefined = 0;

    # convert RRSIG times to DateTime objects with $strp
    my $strp = new DateTime::Format::Strptime(
	pattern   => '%Y%m%d%H%M%S',
	time_zone => 'UTC');
    $fakedate = getFakeDate($fakedate) if defined $fakedate;
    $now = defined $fakedate ? $fakedate : DateTime->now; # now is possibly another date

    my $i = 0;
    # collect data (build result hashes)
    foreach my $domain (keys(%{$bighash})) {
	my $rrsigarray = findValue($bighash->{$domain},'rrsig');
	my (@inc,@exp,@tot);
	my $sigcount = 0;
	foreach my $rrsig (@$rrsigarray) {
	    next if $rrsig->{'typecovered'} eq 'DS'; # skip DS, not from child zone
	    my $sigexp = $strp->parse_datetime($rrsig->{'sigexpiration'});
	    my $exp = int $sigexp->subtract_datetime_absolute($now)->delta_seconds;
	    push @exp, $exp;
	}
	next if int @exp == 0;
	my $minexp = min @exp;
	my $expire = findValue($bighash->{$domain},'soa:expire');
	$soaexpire{sprintf('%.0f',$expire/86400)}++;
	$higher++ if $expire > $minexp;
	$lower++ if $expire < $minexp;

	$res{sprintf('%.0f',($expire/86400)-($minexp/86400))}++ if defined $expire;# if $expire >= $minexp;
	$notdefined++ if not defined $expire;
	$i++;
	last if $i > $limit and $limit > 0;
    }
    # output summary
    map { print "$_: $res{$_}\n"; } sort {$a <=> $b} keys %res;
    print "Expire is higher (bad) than RRSIG lifetime: $higher\n";
    print "Expire is lower (good) than RRSIG lifetime: $lower\n";
    print "(SOA Expire was missing for $notdefined zones...)\n";
    print "Epiration analysis based on total $i zones - the rest was SERVFAIL\n";
    delimiter;
    print "Summary of SOA expire values\n";
    map { print "$_: $soaexpire{$_}\n"; } sort {$a <=> $b} keys %soaexpire;
}

__END__

=head1 NAME

    analyze.pl

=head1 USAGE

analyze -d directory

Required argument(s):

    --directory directory    A directory with WhatWeb JSON files

Optional arguments:

    --limit value            When generating lists, limit the length to this value
    --recache                Recreate our serialized cache (TODO)
    --fake-date YY-MM-DD     Make this the current date for signature lifetime comparisons
    --rcode                  Analyze RCODEs
    --servfail               Toplist of name servers with SERVFAIL
    --servfaillist ns        Get all domains that SERVFAIL on this name server
    --dsduplicates           Toplist of the number of domains that has the same DS record
    --working-ns             Toplist of name servers not NO ERROR on all queries
    --siglife                Analyze RRSIG lifetimes
    --extreme-sigs           List extreme RRSIG lifetimes (inception and expiration larger than 100 days)
    --expiration             Correlate SOA expiration value with lowest RRSIG lifetime
    --algorithms             Analyze DNSSEC algorithms and keylengths
    --nsec3                  Analyze NSEC3 (salt, iterations)

=head1 TODO

Look at the JSON cache, add recache-dommand.
Correlate SOA expire value with lowest RRSIG lifetime.

=head1 AUTHOR

Patrik Wallström <pawal@iis.se>

=cut
