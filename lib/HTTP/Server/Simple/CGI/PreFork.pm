package HTTP::Server::Simple::CGI::PreFork;

use strict;
use warnings;
use Socket;
use Socket6;

our $VERSION = 1.0;

use base qw[HTTP::Server::Simple::CGI];

sub run {
    my ($self, %config) = @_;
    
    if(!defined($config{prefork})) {
        $config{prefork} = 0;
    }

    if(!defined($config{usessl})) {
        $config{usessl} = 0;
    }
    
    if($config{prefork}) {
        # Create new subroutine to tell HTTP::Server::Simple that we want
        # to be a preforking server
        no strict 'refs'; ## no critic (TestingAndDebugging::ProhibitNoStrict)
        *{__PACKAGE__ . "::net_server"} = sub {
            my $server = 'Net::Server::PreFork';
            return $server;
        };

    } else {
        no strict 'refs'; ## no critic (TestingAndDebugging::ProhibitNoStrict)
        *{__PACKAGE__ . "::net_server"} = sub {
            my $server = 'Net::Server::Single';
            return $server;
        };
    }
    
    # SET UP FOR SSL
    if($config{usessl}) {
        # SET UP FOR SSL
        # we need to ovverride the _process_request sub for IPv6. For SSL, we
        # also need to disable the calls to binmode
    
        no strict 'refs'; ## no critic (TestingAndDebugging::ProhibitNoStrict)
        *{__PACKAGE__ . "::_process_request"} =
            sub {
        
            my $self = shift;

            # Create a callback closure that is invoked for each incoming request;
            # the $self above is bound into the closure.
            sub {
        
                $self->stdio_handle(*STDIN) unless $self->stdio_handle;
        
                # Default to unencoded, raw data out.
                # if you're sending utf8 and latin1 data mixed, you may need to override this
                #binmode STDIN,  ':raw';
                #binmode STDOUT, ':raw';
                
                my $remote_sockaddr = getpeername( $self->stdio_handle );
                my ( $iport, $iaddr, $peeraddr );
                if($remote_sockaddr) {
                    eval {
                        # Be fully backwards compatible
                        ( $iport, $iaddr ) = sockaddr_in($remote_sockaddr);
                        $peeraddr = $iaddr ? ( inet_ntoa($iaddr) || "127.0.0.1" ) : '127.0.0.1';
                        1;
                    } or do {
                        # Handle cases where the $remote_sockaddr is an IPv6 structure
                        eval {
                            ( $iport, $iaddr ) = unpack_sockaddr_in6($remote_sockaddr);
                            $peeraddr = inet_ntop(AF_INET6, $iaddr);
                            1;
                        } or do {
                            # What is the best way to handle an unparseable $remote_sockaddr?
                            # Will IPv6 be the "old protocol" one day in our lifetime to be superceded
                            # by something even more complex?
                            #
                            # For now, just return "127.0.0.1", which itself is problematic: What
                            # about the time IPv4 gets switched off and some backend will croak because
                            # the IP is too short?
                            $peeraddr = "127.0.0.1";
                        }
                    }
                }
                
                if(!defined($peeraddr)) {
                    $peeraddr = "";
                } elsif($peeraddr =~ /^\:\:ffff\:(\d+)\./) {
                    # Looks like a IPv4 adress in IPv6 format (e.g. ::ffff:192.168.0.1
                    # turn it into an IPv4 address for backward compatibility
                    $peeraddr =~ s/^\:\:ffff\://;
                }
                
                my ( $method, $request_uri, $proto ) = $self->parse_request;
                
                unless ($self->valid_http_method($method) ) {
                    $self->bad_request;
                    return;
                }
        
                $proto ||= "HTTP/0.9";
        
                my ( $file, $query_string )
                    = ( $request_uri =~ /([^?]*)(?:\?(.*))?/s );    # split at ?
        
                $self->setup(
                    method       => $method,
                    protocol     => $proto,
                    query_string => ( defined($query_string) ? $query_string : '' ),
                    request_uri  => $request_uri,
                    path         => $file,
                    localname    => $self->host,
                    localport    => $self->port,
                    peername     => $peeraddr,
                    peeraddr     => $peeraddr,
                    peerport     => $iport,
                );
        
                # HTTP/0.9 didn't have any headers (I think)
                if ( $proto =~ m{HTTP/(\d(\.\d)?)$} and $1 >= 1 ) {
        
                    my $headers = $self->parse_headers
                        or do { $self->bad_request; return };
        
                    $self->headers($headers);
        
                }
        
                $self->post_setup_hook if $self->can("post_setup_hook");
        
                $self->handler;
            }
        }


    } else {
        # SET UP FOR NON-SSL
        
        # we need to ovverride the _process_request sub for IPv6.
        
        no strict 'refs'; ## no critic (TestingAndDebugging::ProhibitNoStrict)
        *{__PACKAGE__ . "::_process_request"} =
            sub {
        
            my $self = shift;

            # Create a callback closure that is invoked for each incoming request;
            # the $self above is bound into the closure.
            sub {
        
                $self->stdio_handle(*STDIN) unless $self->stdio_handle;
        
                # Default to unencoded, raw data out.
                # if you're sending utf8 and latin1 data mixed, you may need to override this
                binmode STDIN,  ':raw';
                binmode STDOUT, ':raw';
                
                my $remote_sockaddr = getpeername( $self->stdio_handle );
                my ( $iport, $iaddr, $peeraddr );
                if($remote_sockaddr) {
                    eval {
                        # Be fully backwards compatible
                        ( $iport, $iaddr ) = sockaddr_in($remote_sockaddr);
                        $peeraddr = $iaddr ? ( inet_ntoa($iaddr) || "127.0.0.1" ) : '127.0.0.1';
                        1;
                    } or do {
                        # Handle cases where the $remote_sockaddr is an IPv6 structure
                        eval {
                            ( $iport, $iaddr ) = unpack_sockaddr_in6($remote_sockaddr);
                            $peeraddr = inet_ntop(AF_INET6, $iaddr);
                            1;
                        } or do {
                            # What is the best way to handle an unparseable $remote_sockaddr?
                            # Will IPv6 be the "old protocol" one day in our lifetime to be superceded
                            # by something even more complex?
                            #
                            # For now, just return "127.0.0.1", which itself is problematic: What
                            # about the time IPv4 gets switched off and some backend will croak because
                            # the IP is too short?
                            $peeraddr = "127.0.0.1";
                        }
                    }
                }
                if(!defined($peeraddr)) {
                    $peeraddr = "";
                } elsif($peeraddr =~ /^\:\:ffff\:(\d+)\./) {
                    # Looks like a IPv4 adress in IPv6 format (e.g. ::ffff:192.168.0.1
                    # turn it into an IPv4 address for backward compatibility
                    $peeraddr =~ s/^\:\:ffff\://;
                }
                
                my ( $method, $request_uri, $proto ) = $self->parse_request;
                
                unless ($self->valid_http_method($method) ) {
                    $self->bad_request;
                    return;
                }
        
                $proto ||= "HTTP/0.9";
        
                my ( $file, $query_string )
                    = ( $request_uri =~ /([^?]*)(?:\?(.*))?/s );    # split at ?
        
                $self->setup(
                    method       => $method,
                    protocol     => $proto,
                    query_string => ( defined($query_string) ? $query_string : '' ),
                    request_uri  => $request_uri,
                    path         => $file,
                    localname    => $self->host,
                    localport    => $self->port,
                    peername     => $peeraddr,
                    peeraddr     => $peeraddr,
                    peerport     => $iport,
                );
        
                # HTTP/0.9 didn't have any headers (I think)
                if ( $proto =~ m{HTTP/(\d(\.\d)?)$} and $1 >= 1 ) {
        
                    my $headers = $self->parse_headers
                        or do { $self->bad_request; return };
        
                    $self->headers($headers);
        
                }
        
                $self->post_setup_hook if $self->can("post_setup_hook");
        
                $self->handler;
            }
        }

    }

    
    return $self->SUPER::run(%config); # Call parent run()  
}

1;
__END__

=head1 NAME

HTTP::Server::Simple::PreFork - Turn HSS into a a preforking webserver and enable SSL

=head1 SYNOPSIS

Are you using HTTP::Server::Simple::CGI (or are you planning to)? But you want to handle multiple
connections at once and even try out this SSL thingy everyone is using these days?

Fear not, the (brilliant) HTTP::Server::Simple::CGI is easy to extend and this (only modestly well-designed)
module does it for you.

HTTP::Server::Simple::CGI::PreFork should be fully IPv6 compliant.

=head1 DESCRIPTION

This module is a plugin module for the "Commands" module and handles
PostgreSQL admin commands scheduled from the WebGUI.

=head1 Configuration

Obviously, you want to read the HTTP::Server::Simple documentation for the bulk
of configuration options. Since we also overload the base tcp connection class
with Net::Server, you might also want to read the documentation for that.

We use two Net::Server classes, depending on if we are preforking or single
threaded:

Net::Server::Single for singlethreaded

Net::Server::PreFork for multithreaded

In addition to the HTTP::Server::Simple configuration,
there are only two additional options (in the hash to) the
run() method: usessl and prefork.

=head2 prefork

Basic usage:

$myserver->run(prefork => 1):

Per default, prefork is turned off (e.g. server runs singlethreaded). This
is very usefull for debugging and backward compatibility.

Beware when forking: Keep in mind how database and filehandles behave. Normally,
you should set up everything before the run method (cache files, load confiugurations,...),
then close all handles and run(). Then, depending on your site setup, either open a
database connection for every request and close it again, or (and this is the better
performing option) open a database handle at every request you don't have an open handle yet -
since we are forking, every thread get's its own unique handle while not constantly opening and
closing the handles.

Optionally, you can also add all the different options of Net::Server::Prefork like "max_servers" on
the call to run() to optimize your configuration.

=head2 usessl

Caution: SSL support is experimental at best. I got this to work with a lot of warnings,
sometimes it might not work at all. If you use this, please send patches!

Set this option to 1 if you want to use SSL (default is off). For SSL to actually work, need
to add some extra options (required for the underlying Net::Server classes, something like this
usually does the trick:

$webserver->run(usessl => 1,
                proto => 'ssleay');
                "--SSL_key_file"=> 'mysite.key',
                "--SSL_cert_file"=>'mysite.crt',
                );


=head2 run

Internal functions that overrides the HTTP::Server::Simple::CGI run function. Just as explained above.

=head1 IPv6

This module overrides also the pure IPv4 handling of HTTP::Server::Simple::CGI and turns
it into an IPv4/IPv6 multimode server.

Only caveat here is, that you need the Net::Server modules in version
0.99.6.1 or higher. Version 0.99 and lower only supports IPv4.

For some backward compatibility issues, the build requirements do *not* automatically pull
that Net::Server version (only "0.99 or higher"). It's up to you to check that the correct
version is installed.

=head1 WARNING

This module "patches" HTTP::Server::Simple by overloading one
of the functions. Updating HTTP::Server::Simple *might* break
something. While this is not very likely, make sure to test
updates before updating a production system!

=head1 AUTHOR

Rene Schickbauer, E<lt>rene.schickbauer@gmail.comE<gt>

This module borrows heavily from the follfowing modules:

HTTP::Server::Simple by Jesse Vincent
Net::Server by Paul T. Seamons

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=head1 THANKS

Special thanks to Jesse Vincent for giving me quick feedback when i needed it.

Also thanks to the countless PerlMonks helping me out when i'm stuck. This module
is dedicated to you!

=cut

