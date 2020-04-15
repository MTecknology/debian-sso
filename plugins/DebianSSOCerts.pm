package Lemonldap::NG::Portal::Plugins::DebianSSOCerts;

use strict;

use Moo;
use Dpkg::IPC;
use Date::Parse;

use constant openssl => '/home/xavier/dev/github/debsso/openssl.sh';

# Token timeout for GPG
use constant GPGTOKENTIMEOUT => 600;

# Authentication level needed for high verified cert
use constant HIGHAUTHLEVEL => 5;

# Session attribute to retrieve "mail"
my $MAIL = 'mail';

extends 'Lemonldap::NG::Portal::Main::Plugin',
  'Lemonldap::NG::Portal::Lib::SMTP';

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
        $ott->timeout(GPGTOKENTIMEOUT);
        return $ott;
    }
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
                { authenticationLevel => HIGHAUTHLEVEL } );
        }
        else {
            return $self->p->sendError( $req, 'Token expired' );
        }
    }
    if ( $req->userData->{authenticationLevel} < HIGHAUTHLEVEL ) {
        my $mail = $req->userData->{$MAIL}
          or return $self->p->sendError( $req, 'Unable to retrieve mail', 500 );

        # DEBUG
        $self->conf->{mailFrom} = 'yadd@debian.org';
        $mail = 'yadd@debian.org';

        # /DEBUG
        my $token = $self->ottSecure->createToken( { secureCert => 1 } );
        my $url =
          $self->conf->{portal} . "certs/enrollSecure?secureToken=$token";
        my $txt = "Go to $url to get a higher authentication level";
        spawn(
            exec => [
                qw(gpg --homedir /dev/null --keyring /usr/share/keyrings/debian-keyring.gpg --list-keys),
                $mail
            ],
            wait_child => 1,
            nocheck    => 1,
        );
        if ($@) {
            return $self->p->sendError( $req,
                'Mail not found in DD GPG database' );
        }
        my $out;
        spawn(
            exec => [
                qw(gpg --encrypt --armor --yes --keyring /usr/share/keyrings/debian-keyring.gpg --trust-model always -r),
                $mail
            ],
            from_string => \$txt,
            to_string   => \$out,
            wait_child  => 1,
            nocheck     => 1,
        );
        $self->send_mail( $mail, 'High verification mail', $out );
        return $self->p->sendHtml(
            $req, 'error',
            params => {
                RAW_ERROR       => 1,
                AUTH_ERROR_TYPE => 'warning',
                RAW_ERROR       => 'GPG encrypted message sent, click on the link'
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
            LEVEL => ($req->userData->{authenticationLevel} == HIGHAUTHLEVEL),
            TOKEN => $self->ott->createToken(
                { id => $req->userData->{_session_id} }

                #{ user => $req->userData }
            ),
        }
    );
}

# Sing CSR
sub signCSR {
    my ( $self, $req ) = @_;
    my $highLevel = ($req->userData->{authenticationLevel} == HIGHAUTHLEVEL);
    my $id = $self->ott->getToken( $req->param('token') );
    unless ( $id and $id->{id} eq $req->userData->{_session_id} ) {
        $self->userLogger->notice('Bad token');
        return $self->p->sendError( $req, 'Bad token' );
    }
    my $csr  = $req->param('csr');
    my $days = $req->param('validity') || 365;
    $days = 365 if $days > 365 or $days < 1;
    my $out;

    # Check CSR
    spawn(
        exec        => [ openssl, qw'req -noout -text' ],
        from_string => \$csr,
        to_string   => \$out,
        wait_child  => 1,
        nocheck     => 1,
    );
    if ($@) {
        $self->p->sendError( $req, 'Bad request' );
    }

    # Insert here request checks
    if (
        $out !~ /Subject: CN = (\S+) \+ O = Debian \+ OU = Debian Developers/s )
    {
        $self->userLogger->error("Bad CSR : $out");
        return $self->p->sendError( $req, 'Bad CSR request: ' . $out );
    }

    # Sign cert
    spawn(
        exec => [
            openssl,
            qw'x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -days', $days
        ],
        from_string => \$csr,
        to_string   => \$out,
        wait_child  => 1,
        nocheck     => 1,
    );
    if ($@) {
        $self->p->sendError( $req, 'Bad request' );
    }
    my $crt = $out;

    # Retrive serial number
    spawn(
        exec        => [ openssl, qw'x509 -noout -text' ],
        from_string => \$crt,
        to_string   => \$out,
        wait_child  => 1,
        nocheck     => 1,
    );
    if ($@) {
        $self->p->sendError( $req, 'Bad request' );
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
    foreach(@$currentCert) {
        print STDERR '# '.str2time($_->{expires})." $now\n";
        $_->{expired} = 1 if str2time($_->{expires}) < $now;
    }
    return $currentCert;
}

1;
