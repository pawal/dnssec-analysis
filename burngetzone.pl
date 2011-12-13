#!/usr/bin/perl

use warnings;
use strict;

use Pod::Usage;
use Getopt::Long;
use Data::Dumper;
use Net::DNS;
use Net::DNS::SEC;

my $DEBUG = 0; # set to true if you want some debug output
my $file;      # input zone file
my $limit = 0; # impose limit ($maxlines) for testing purposes

my $maxlines = 50000; # max number of lines to read for example...
my $i = 0;   # line counter

my $par = 0; # think of the parenthesis
my $rr = ""; # global rr var

# read and parse the zonefile, building a hash with the data we want
sub readZone
{
    my $zoneFile = shift;
    my %dnsData;

    print " -=> Reading and parsing <=-\n" if $DEBUG;

    open(ZONE, "<$zoneFile") or die "can't read file: $zoneFile";
    while (<ZONE>)
    {
        last if $i++ > $maxlines and $limit;

	# remove comments and empty lines
	next if /^\s*$/;     # jump empty lines
	next if /^\;/;       # jump all-comment lines
	s/^(.*)\s*\;.*$/$1/; # remove comments
	my $line = $_;

	# parentheses states to get whole RR
	$rr = $line if not $par;
	$rr.= $line if $par;
	$par = 1 if $line =~ /\($/;
	$par = 0 if $line =~ /\)\s?$/;

	# we have got a full RR, lets parse and store
	if (not $par)
	{
	    if ($rr =~ /IN\s+DS/)
	    {
		my $dnsrr = Net::DNS::RR->new($rr);
		if ($dnsrr->type eq 'DS')
		{
		    print $dnsrr->name.":".$dnsrr->digest."\n" if $DEBUG;
		    $dnsData{$dnsrr->name}->{'DS'}->{$dnsrr->digest} = $dnsrr;
		}
	    }
	    elsif ($rr =~ /IN\s+DNSKEY/)
	    {
		my $i = 0;
		my $dnsrr = Net::DNS::RR->new($rr);
		if ($dnsrr->type eq 'DNSKEY')
		{
		    print $dnsrr->name.":".$dnsrr->keytag."\n" if $DEBUG;
		    $dnsData{$dnsrr->name}->{'DNSKEY'}->{$i++} = $dnsrr;
		}
	    }
	}
    }
    close ZONE;
    return \%dnsData;
}

sub printList {
    my $dnsData = shift;
    foreach my $name (keys %{$dnsData})
    {
	print "$name\n";
    }
}

sub main() {
    my $help = 0;
    GetOptions('help|h' => \$help,
	       'file|f=s' => \$file,
	       'limit|l' => \$limit,
	       'debug' => \$DEBUG,
	      ) or pod2usage(2);
    pod2usage(1) if($help);
    pod2usage(1) if(not defined $file);

    my $dnsData = readZone($file);
    printList($dnsData);
}

main;

# get the zone, output all domains with a DS to a file
# don't care about any content here

=head1 NAME

burngetzone

=head1 SYNOPSIS

   burngetzone.pl -f zonefile

=head1 DESCRIPTION

   outputs a list of domains with DS

=head1 AUTHOR

   Patrik Wallstrom <pawal@iis.se>

=cut
