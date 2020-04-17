package Lemonldap::NG::Portal::Plugins::DebianSSOCerts;

use strict;

use Moo;
use IPC::Run;
use Date::Parse;
use File::Temp;

extends 'Lemonldap::NG::Portal::Main::Plugin',
  'Lemonldap::NG::Portal::Lib::SMTP';

# lemonldap-ng.ini parameters (section [portal]
has openssl => (
    is      => 'ro',
    default => sub {
        $_[0]->conf->{openssl} || '/var/lib/debian-sso/openssl.sh';
    },
);

has gpgDatabases => (
    is      => 'ro',
    default => sub {
        $_[0]->conf->{gpgDatabases}
          || '/usr/share/keyrings/debian-nonupload.gpg /usr/share/keyrings/debian-keyring.gpg';
    },
);

has gpgCertTokenTimeout => (
    is      => 'ro',
    default => sub {
        $_[0]->conf->{gpgCertTokenTimeout} || 600;
    },
);

has highCertAuthnLevel => (
    is      => 'ro',
    default => sub {
        $_[0]->conf->{highCertAuthnLevel} || 5;
    },
);

has mailAttribute => (
    is      => 'ro',
    default => sub {
        $_[0]->conf->{mailAttribute} || 'mail';
    },
);

has opensslSignArgs => (
    is      => 'ro',
    default => sub {
        $_[0]->conf->{opensslSignArgs}
          || 'x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -days';
    },
);

has opensslHighSignArgs => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]->opensslSignArgs;
    },
);

has ott => (
    is      => 'rw',
    lazy    => 1,
    default => sub {
        my $ott = $_[0]->{p}->loadModule('::Lib::OneTimeToken');
        return $ott;
    }
);

has ottSecure => (
    is      => 'rw',
    lazy    => 1,
    default => sub {
        my $ott = $_[0]->{p}->loadModule('::Lib::OneTimeToken');
        $ott->timeout( $_[0]->gpgCertTokenTimeout );
        return $ott;
    }
);

has tmpDir => (
    is      => 'ro',
    default => sub {
        return File::Temp::tempdir( CLEANUP => 1 );
    },
);

sub init {
    my ($self) = @_;
    $self->addAuthRouteWithRedirect(
        certs => {
            enroll       => 'enroll',
            enrollSecure => 'enrollSecure',
            '*'          => 'run',
        },
        [ 'GET', 'POST' ]
    );
    $self->addAuthRouteWithRedirect(
        certs => { enroll => 'signCSR' },
        ['POST']
    );
    return 1;
}

# This method send a GPG encrypted message and upgrade authentication level
# then
sub enrollSecure {
    my ( $self, $req ) = @_;
    if ( my $token = $req->param('secureToken') ) {
        my $value;
        if (    $value = $self->ottSecure->getToken($token)
            and $value->{secureCert} )
        {
            $self->p->updateSession( $req,
                { authenticationLevel => $self->highCertAuthnLevel } );
        }
        else {
            return $self->p->sendError( $req, 'Token expired' );
        }
    }
    if ( $req->userData->{authenticationLevel} < $self->highCertAuthnLevel ) {
        my $mail = $req->userData->{ $self->mailAttribute }
          or return $self->p->sendError( $req, 'Unable to retrieve mail', 500 );

        my $token = $self->ottSecure->createToken( { secureCert => 1 } );
        my $url =
          $self->conf->{portal} . "certs/enrollSecure?secureToken=$token";
        my $txt = "Go to $url to get a higher authentication level";
        my ( $out, $err );
        IPC::Run::run( [
                qw(gpg --list-keys --homedir),
                $self->tmpDir,
                (
                    map { ( '--keyring', $_ ) } split /,?\s+/,
                    $self->gpgDatabases
                ),
                $mail
            ],
            ,
            \$out,
            \$err,
        );

        if ($?) {
            $self->userLogger->notice(
                "gpg failed to find user in database: $err");
            return $self->p->sendError( $req,
q{you requested this, but you can't use it unless your official key made it all the way into the package and found a release}
            );
        }
        IPC::Run::run( [
                qw(gpg --encrypt --armor --yes --trust-model always -r),
                $mail,
                (
                    map { ( '--keyring', $_ ) } split /,?\s+/,
                    $self->gpgDatabases
                ),
            ],
            \$txt,
            \$out,
            \$err,
        );
        if ($?) {
            $self->logger->error("gpg error: $err");
            return $self->p->sendError( $req, 'gpg failed' );
        }
        $self->send_mail( $mail, 'High verification mail', $out );
        return $self->p->sendHtml(
            $req, 'error',
            params => {
                RAW_ERROR       => 1,
                AUTH_ERROR_TYPE => 'warning',
                RAW_ERROR => 'GPG encrypted message sent, click on the link'
            }
        );
    }
    else {
        return $self->enroll($req);
    }
}

# Display cert list
sub run {
    my ( $self, $req ) = @_;
    my $certs = $self->getCurrentCerts($req);
    if ( $req->method eq 'POST' ) {

        # Revoke certificate
        my $serial = $req->param('serial');
        my $certid = $serial;
        $certid =~ s/://g;

        # Insert here CRL update and generation using $certid

        # Update cert list
        @$certs = map { $_->{serial} eq $serial ? () : $_ } @$certs;
        $self->p->updatePersistentSession( $req, { debianCerts => $certs } );
    }
    return $self->p->sendHtml( $req, 'certs', params => { CERTS => $certs } );
}

# Display CSR enrollment page
sub enroll {
    my ( $self, $req ) = @_;
    return $self->p->sendHtml(
        $req,
        'certenroll',
        params => {
            LEVEL => (
                $req->userData->{authenticationLevel} ==
                  $self->highCertAuthnLevel
            ),
            TOKEN => $self->ott->createToken(
                { id => $req->userData->{_session_id} }

                #{ user => $req->userData }
            ),
            MAIL => $req->userData->{ $self->mailAttribute },
        }
    );
}

# Sing CSR
sub signCSR {
    my ( $self, $req ) = @_;
    my $highLevel =
      ( $req->userData->{authenticationLevel} == $self->highCertAuthnLevel );
    my $id = $self->ott->getToken( $req->param('token') );
    unless ( $id and $id->{id} eq $req->userData->{_session_id} ) {
        $self->userLogger->notice('Bad token');
        return $self->p->sendError( $req, 'Bad token' );
    }
    my $csr  = $req->param('csr');
    my $days = $req->param('validity') || 365;
    $days = 365 if $days > 365 or $days < 1;
    my ( $out, $err );

    # Check CSR
    IPC::Run::run( [ $self->openssl, qw'req -noout -text' ],
        \$csr, \$out, \$err, );
    if ($?) {
        $self->userLogger->error("Bad CSR request: $err");
        $self->p->sendError( $req, 'Bad request' );
    }

    # Insert here request checks
    if (
        $out !~ /Subject: CN = (\S+) \+ O = Debian \+ OU = Debian Developers/s )
    {
        $self->userLogger->error("Bad CSR : $out");
        return $self->p->sendError( $req, 'Bad CSR request: ' . $out );
    }
    my $cn       = $1;
    my $userMail = $req->userData->{ $self->mailAttribute };
    if ( $cn !~ /\Q$userMail\E/ ) {
        return $self->p->sendError( $req,
            "Mail mistamtch in CN, this should be $userMail", 400 );
    }

    # Sign cert
    my $cmd =
      ( $highLevel ? $self->opensslHighSignArgs : $self->opensslSignArgs );
    IPC::Run::run( [ $self->openssl, ( split /\s+/, $cmd ), $days ],
        \$csr, \$out, \$err, );
    if ($?) {
        $self->userLogger->error("Bad CSR request: $err");
        $self->p->sendError( $req, 'Bad request' );
    }
    my $crt = $out;

    # Retrive serial number
    IPC::Run::run( [ $self->openssl, qw'x509 -noout -text' ],
        \$crt, \$out, \$err, );
    if ($?) {
        $self->logger->error("Unable to read generated certificate: $err");
        $self->p->sendError( $req, 'openssl error', 500 );
    }
    unless ( $out =~ /Serial Number:\s+([0-9a-f:]+)\n/s ) {
        $self->logger->error("Unable to find serial number in: $out");
        return $self->p->sendError( $req, 'Something wrong happens...', 500 );
    }
    my $serial = $1;
    $out =~ /Not After : (.*?)\n/;
    my $expires     = $1;
    my $currentCert = $self->getCurrentCerts($req);
    push @{$currentCert},
      {
        serial  => $serial,
        expires => $expires,
        comment => $req->param('comment') || '',
        ( $highLevel ? ( highLevel => 1 ) : () ),
      };
    $self->p->updatePersistentSession( $req, { debianCerts => $currentCert } );

    if ( $req->wantJSON ) {
        return $self->p->sendJSONresponse( $req,
            { result => 1, cert => $crt } );
    }
    else {
        return ( 200, [ 'Content-Type' => 'text/plain' ], [$crt] );
    }
}

# Internal methods

sub getCurrentCerts {
    my ( $self, $req ) = @_;
    my $user = $req->userData->{ $self->conf->{whatToTrace} };
    my $currentCert =
      $self->p->getPersistentSession($user)->data->{debianCerts} || [];
    my $now = time;
    foreach (@$currentCert) {
        print STDERR '# ' . str2time( $_->{expires} ) . " $now\n";
        $_->{expired} = 1 if str2time( $_->{expires} ) < $now;
    }
    return $currentCert;
}

1;
