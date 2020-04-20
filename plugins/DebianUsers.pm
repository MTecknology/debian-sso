# Lemonldap::NG plugin to register authenticated users (GitHub, LinkedIn,...)
# but not known in our SQL database
#
# It handles 2 endpoints:
#  * LLNG internal getUser() method is replaced by check() which displays
#    form if needed
#  * https://portal/debianregister : receive registration data from form

package Lemonldap::NG::Portal::Plugins::DebianUsers;

use strict;
use Moo;

# Inheritance:
#  * LLNG plugin
#  * SQL object (uses DBI parameters declared in authentication scheme) - non-DD database
#    Provides $self->dbh, a DBI object
#  * LDAP object (uses LDAP parameters declared in authentication scheme) - DD database
#    Provides $self->ldap, a Net::LDAP object
extends 'Lemonldap::NG::Portal::Main::Plugin',
  'Lemonldap::NG::Portal::Lib::DBI',
  'Lemonldap::NG::Portal::Lib::LDAP';

# LLNG constants used in `check()` responses
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_INFO
  PE_SENDRESPONSE
);

# Parameters from lemonldap-ng.ini with their default values
#
# Timeout to register, default 10 mn
has debianRegisterTimeout => (
    is      => 'ro',
    default => sub {
        $_[0]->conf->{debianRegisterTimeout} || 600;
    },
);

# Nickname regexp, default 3 to 20 alphanum-or-"-" chars. Starts with a
# alphanum char
has debianNicknameRegexp => (
    is      => 'ro',
    default => sub {
        my $re = $_[0]->conf->{debianNicknameRegexp} || '^\w[\w\-]{2,19}$';
        return qr/$re/;
    },
);

# SQL fields
# Required:
# * uid: LinkedIn uid
# * mail: mail given by LinkedIn (may be changed later)
# * username: chosen Debian uid
# * displayname: fullname to display
# * firstname
# Optional:
# * lastname
# * gpgkey: GPG key
# * sshkey: SSK key
our @fields =
  (qw(uid mail username displayname firstname lastname gpgkey sshkey));

# NB: uid and mail are required but provided by authentication mechanism
our @requiredFields = (qw(username displayname firstname));

# Sessions parameter: this plugin uses macros that returns wanted data:
#  * mail: should be
#    `($linkedIn_emailAddress ? $linkedIn_emailAddress : $github_emailAddress ? $github_emailAddress : "$uid\@debian.org" )`

# Internal getters
#
# One-time-token instance
has ott => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        my $ott = $_[0]->{p}->loadModule('::Lib::OneTimeToken');
        $ott->timeout( $_[0]->debianRegisterTimeout );
        return $ott;
    }
);

# INTERFACE WITH LLNG
#
# LLNG Entry point to catch authentication requests before "search" step:
# launches check() instead of LLNG internal getUser() method
use constant aroundSub => { getUser => 'check' };

# Declare /debianregister route (used by registration form).
# Only POST requests are accepted here
#
# No need to launch  ::Lib::DBI and ::Lib::LDAP init() methods here: already
# launched by authentication modules
sub init {
    my ($self) = @_;
    $self->addUnauthRoute( debianregister => 'register', ['POST'] );
    return 1;
}

# RUNNING METHODS

# Checks if non-DD user is known from SQL database. Displays registration
# form else
#
# This method is launched during auth process, it must returns LLNG constants
#
# Response: Lemonldap::NG::Portal::Main::Constants constant
sub check {
    my ( $self, $sub, $req ) = @_;

    # Launch getUser and intercept result
    my $res = $sub->($req);

    # If getUser succeeds, no need to do anything
    return PE_OK if $res == PE_OK;

    # USER NOT FOUND IN USERS DATABASE

    # Don't intercept DD requests
    return $res if $self->p->getModule( $req, "auth" ) eq 'LDAP';

    # Get linkedIn/GitHub data
    $self->p->setAuthSessionInfo($req);

    # Calculate macros
    $self->p->setMacros($req);

   # Display registration form: since we are in auth process, direct PSGI output
   # is not allowed here, we must use this hook
    $req->response( $self->form($req) );
    return PE_SENDRESPONSE;
}

# Register user
#
# This method receives POST requests from registration form (POST requests only
# as declared in init() method)
#
# Response: PSGI format
sub register {
    my ( $self, $req ) = @_;

    # Objects inherited from LLNG libs (configured via manager:
    # "General Parameters" => "authentication modules"):
    #  * $self->dbh : SQL  connection (non DD users, registered using this
    #                 plugin)
    #  * $self->ldap: LDAP connection (DD users)

    # 0 - get data
    my $nickname = $req->param('username');
    my $token    = $req->param('token');

    # 1 - check token
    my $session = $self->ott->getToken($token);
    unless ($session) {
        return $self->sendError( $req,
            'Bad token or token expired, restart registration process', 400 );
    }
    $req->user( $session->{user} );
    $req->sessionInfo( $session->{data} );

    # Check username string
    if ( $nickname !~ $self->debianNicknameRegexp ) {
        return $self->form( $req, 'Nickname not allowed' );
    }

    # Check other fields
    my $error = $self->_checkOtherFields($req);
    if ($error) {
        return $self->form( $req, $error );
    }

    # 2 - verify that nickname does not already exist in LDAP or SQL DB
    my $res = eval { $self->_checknickname($nickname) };
    if ($@) {
        return $self->p->sendError( $req, 'Registration databases seems down',
            500 );
    }

    # 2.1 - case OK (nickname not used)
    if ($res) {
        return $self->_registerUser($req);
    }

    # 2.2 - case NOK, display form
    else {
        return $self->form( $req,
            'Nickname already exists, choose another one' );
    }
}

# Internal method to populate and display form
#
# Response: PSGI format
sub form {
    my ( $self, $req, $error ) = @_;
    my $token = $self->ott->createToken(
        { user => $req->user, data => $req->sessionInfo } );
    if ( $req->wantJSON ) {
        return $self->p->sendJSONresponse( $req,
            { result => ( $error ? 0 : 1 ), error => $error, token => $token, }
        );
    }
    else {
        return $self->p->sendHtml(
            $req,
            'debianRegistration',
            params => {
                USER  => $req->user,
                TOKEN => $token,
                ERROR => $error,
            }
        );
    }
}

# Internal boolean function that checks if proposed nickname is already used
sub _checknickname {
    my ( $self, $nickname ) = @_;

    # 1 - LDAP
    $self->validateLdap;

    unless ( $self->ldap ) {
        $self->logger->error('LDAP seems down');
        die;
    }

    $self->bind();

    my $mesg = $self->ldap->search(
        base   => $self->conf->{ldapBase},
        scope  => 'sub',
        filter => $self->filter->( { user => $nickname } ),
        defer  => $self->conf->{ldapSearchDeref} || 'find',
        attrs  => $self->attrs,
    );
    if ( $mesg->code() != 0 ) {
        $self->logger->error( 'LDAP returned an error: ' . $mesg->error );
        die;
    }

    # Fail if a DD exists with this nickname
    return 0 if $mesg->entry(0);

    # 2 - SQL DB
    my $sth;
    eval {
        $sth = $self->dbh->prepare(
            'SELECT username from ' . $self->table . ' WHERE username=?' );
        $sth->execute($nickname);
    };
    if ($@) {
        $self->logger->error("SQL DB returned an error: $@");
        die;
    }
    return 0 if $sth->fetchrow_hashref();

    # Well, nickname not found anywhere, let's agree this nickname
    return 1;
}

# Internal function that checks if fields are well filed.
# Return an error to display if needed
sub _checkOtherFields {
    my ( $self, $req ) = @_;

    # Check if required fields are set
    my @missings;
    foreach (@requiredFields) {
        push @missings, $_ unless $req->param($_);
    }
    if (@missings) {
        return 'These fields are required: ' . join( ', ', @missings );
    }

    # TODO: insert here fields checks

    # No error:
    return '';
}

# Real registration method: insert fields in SQL DB
#
# Response: PSGI format
sub _registerUser {
    my ( $self, $req ) = @_;
    my $sth;

    # TODO: fix that
    my %values = ( map { ( $_ => $req->param($_) ) } @fields );
    $values{uid}  = $req->sessionInfo->{linkedIn_id};
    $values{mail} = $req->sessionInfo->{linkedIn_emailAddress};

    # Filter fields: only those who are filed are taken in this query
    my @_fields = map { $values{$_} ? ($_) : () } @fields;
    eval {
        $sth =
          $self->dbh->prepare( 'INSERT INTO '
              . $self->table . ' ('
              . join( ',', @_fields )
              . ") VALUES ("
              . join( ",", map { '?' } @_fields )
              . ")" );
        $sth->execute( map { $values{$_} } @_fields );
    };
    if ($@) {

        # If connection isn't available, error is displayed by dbh()
        $self->logger->error("DBI error: $@") if ( $self->_dbh );
        return $self->form( $req, 'Error form database, try later' );
    }

    # Finish auth process and display registration message

    # Prepare message (HTML acccepted here)
    $req->info('Successfully registered');

    # Restart Choices initialization
    $self->p->extractFormInfo($req);
    $self->p->getUser($req) || $self->logger->error("User registered but not found, verify your configuration");;

    # Launch remaining LLNG methods (`do()` from
    # Lemonldap::NG::Portal::Main::Run will do the job. Just to declare
    # methods to launch (keeping authentication from remote system)
    return $self->p->do(
        $req,
        [

            # Plugins entryPoints
            @{ $self->p->betweenAuthAndData },

            # Methods that populates session data
            $self->p->sessionData,

            # Plugins entryPoints
            @{ $self->p->afterData },

            # Methods that validate session
            $self->p->validSession,

            # Plugins entryPoints
            @{ $self->p->endAuth },

            # Fake entrypoint to force displaying registration message
            sub { PE_INFO },
        ]
    );
}

1;
