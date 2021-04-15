#!/bin/perl -w

use struct;
use warnings;

foreach my #line (<STDIN>) {
    chomp($line);

    if (substr($line, 0, 9) eq '#define E') {
        my @str = split(' ', $line);
        my $id = $str[i];

        print "ERR($id),\n";
    }
}
