#!/usr/bin/perl

use JSON;                        # for input and output of data files
use Data::Dumper;                # debugging
use Encode qw< encode decode >;  # UTF-8 stuff
use List::Util qw[min max sum];  # for finding min and max values in lists
use Data::Serializer;            # for serializing data (needs work)
use Getopt::Long;                # option handling
use DateTime::Format::Strptime;  # converting RRSIG times
use Pod::Usage;                  # documentation

# GLOBALS

### find zero byte files
# find . -type f -size 0|wc -l

### OPTIONS
my $analyzeRcode;
my $analyzeServfail;
my $analyzeServfailList;
my $analyzeWorkingNS;
my $analyzeSigLife;
my $analyzeExtremeSigs;
my $analyzeAlgorithms;
my $anaLyzeNSEC3;
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
    'working-ns'     => \$analyzeWorkingNS,
    'siglife'        => \$analyzeSigLife,
    'extreme-sigs'   => \$analyzeExtremeSigs,
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
#pod2usage(-exitstatus => 0);
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

    foreach my $domain (keys(%{$bighash})) {
	$result{'A:'.findValue($bighash->{$domain},          'A:rcode')}++;
	$result{'MX:'.findValue($bighash->{$domain},         'MX:rcode')}++;
	$result{'SOA:'.findValue($bighash->{$domain},        'soa:rcode')}++;
	$result{'NSEC3PARAM:'.findValue($bighash->{$domain}, 'nsec3param:rcode')}++;
	$result{'DNSKEY:'.findValue($bighash->{$domain},     'dnskey:rcode')}++;
    }
    foreach my $key (sort keys(%result)) {
	print "$key: $result{$key}\n";
    }
}

# list of total servfails
sub analyzeServfails {
    my $bighash = shift;
    my %result;

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
	}
    }
    my $i = 0;
    foreach my $key (sort { $result{$b} <=> $result{$a} } keys %result) {
	print "$key: $result{$key}\n";
	$i++;
	last if $i > $limit and $limit > 0;
    }
}

sub getServfailList {
    my $bighash = shift;
    my $nameserver = shift;
    my @result;

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
    foreach my $domain (sort @result) {
	print "SERVFAIL $nameserver: $domain\n";
    }
}

# list of all NS with NOERROR
sub analyzeWorkingNS {
    my $bighash = shift;
    my %result;

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
	map { $ds{$_->{'digtype'}}++ }       @$dss;
	map { $rrsig{$_->{'algorithm'}}++ }  @$rrsigs;
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
	next if not defined $nsec3param->{'hashalgo'}; # TODO: this line does not work...
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
    map { print "NSEC3 Hash algorithm: $_: $hashalgo{$_}\n"; } sort {$a <=> $b} keys %hashalgo;
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
    --fake-date YY-MM-DD     Make this the current date for signature lifetime comparisons (TODO)
    --rcode                  Analyze RCODEs
    --servfail               Toplist of name servers with SERVFAIL
    --servfaillist ns        Get all domains that SERVFAIL on this name server
    --working-ns             Toplist of name servers not NO ERROR on all queries
    --siglife                Analyze RRSIG lifetimes
    --extreme-sigs           List extreme RRSIG lifetimes (inception and expiration larger than 100 days)
    --algorithms             Analyze DNSSEC algorithms and keylengths
    --nsec3                  Analyze NSEC3 (salt, iterations)

=head1 TODO

All of the analysis that we could do is not finished. For example key algorithms, NSEC3 iterations etc.
Set a fake 'current' date for checking signatures.

=head1 AUTHOR

Patrik Wallström <pawal@iis.se>

=cut
