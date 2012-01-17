#!/usr/bin/perl

use JSON;                        # for input and output of data files
use Data::Dumper;                # debugging
use Encode qw< encode decode >;  # UTF-8 stuff
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
	analyzeRcodes($alldata);
	delimiter;
    }
    if ($analyzeServfail) {
	analyzeServfails($alldata);
	delimiter;
    }
    if ($analyzeServfailList) {
	getServfailList($alldata,$analyzeServfailList);
	delimiter;
    }
    if ($analyzeWorkingNS) {
	analyzeWorkingNS($alldata);
	delimiter;
    }
    if ($analyzeSigLife) {
	analyzeSigLifetimes($alldata,$fakedate);
	delimiter;
    }

    print "Domains with data: ".scalar keys(%super)."\n";
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

# discover the validity lifetimes of the signatures
sub analyzeSigLifetimes {
    my $bighash = shift;
    my $fakedate = shift;
    my $now;

    my %exps; # expiration times in days
    my %incs; # inception times in days
    my %life; # difference between expiration and inception in days

    # convert RRSIG times to DateTime objects with $strp
    my $strp = new DateTime::Format::Strptime(
	pattern   => '%Y%m%d%H%M%S',
	time_zone => 'UTC');
#	on_error  => 'croak');
    $fakedate = getFakeDate($fakedate) if defined $fakedate;
    $now = defined $fakedate ? $fakedate : DateTime->now; # now is possibly another date

    my $i = 0; # temp limit
    foreach my $domain (keys(%{$bighash})) {
	my $rrsigarray = findValue($bighash->{$domain},'rrsig');
	my ($min,$max,$mintotal,$maxtotal) = (0,0,0,0); # per domain statistics
	    my $sigexp = $strp->parse_datetime($rrsig->{'sigexpiration'});
	    my $siginc = $strp->parse_datetime($rrsig->{'siginception'});
	    my $inc = int $siginc->subtract_datetime_absolute($now)->delta_seconds / 86400;
	    my $exp = int $sigexp->subtract_datetime_absolute($now)->delta_seconds / 86400;
	    my $tot = int $sigexp->subtract_datetime_absolute($siginc)->delta_seconds / 86400;
	    $incs{$inc}++; # build result hash with inception times
	    $exps{$exp}++; # build result hash with expiration times
	    $life{$tot}++; # build result hash with total lifetimes
	}
	$i++;
	last if $i > $limit and $limit > 0;
    }
    print "Signature inception (days, count)\n";
    foreach my $days (sort {$a <=> $b} keys %incs) {
	print "$days,".$incs{$days}."\n";
    }
    delimiter;
    print "Signature expiration (days, count)\n";
    foreach my $days (sort {$a <=> $b} keys %exps) {
	print "$days,".$exps{$days}."\n";
    }
    delimiter;
    print "Total signature lifetimes (days, count)\n";
    foreach my $days (sort {$a <=> $b} keys %life) {
	print "$days,".$life{$days}."\n";
    }
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
    --working-ns             Toplist of name servers not NO ERRORR on all queries
    --siglife                Analyze RRSIG lifetimes (TODO)
    --keyalgo                Analyze DNSKEY algorithms (TODO)
    --iterations             Analyze NSEC3 iterations (TODO)

=head1 TODO

All of the analysis that we could do is not finished. For example key algorithms, NSEC3 iterations etc.
Set a fake 'current' date for checking signatures.

=head1 AUTHOR

Patrik Wallström <pawal@iis.se>

=cut
