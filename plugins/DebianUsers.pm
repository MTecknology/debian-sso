package Lemonldap::NG::Portal::Plugins::DebianUsers;

use strict;

use Moo;

extends 'Lemonldap::NG::Portal::Main::Plugin',
  'Lemonldap::NG::Portal::Lib::DBI',
  'Lemonldap::NG::Portal::Lib::LDAP';

use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
);

# Parameters
#
# Timeout to register, default 10 mn
has debianRegisterTimeout => (
    is      => 'ro',
    default => sub {
        $_[0]->conf->{debianRegisterTimeout} || 600;
    },
);

# LLNG Entry point to catch authentication requests before "search" step
use constant aroundSub => { getUser => 'check' };

# Internal getters
#
# One-time-token instance
has ott => (
    is      => 'rw',
    lazy    => 1,
    default => sub {
        my $ott = $_[0]->{p}->loadModule('::Lib::OneTimeToken');
        $ott->timeout( $_[0]->debianRegisterTimeout );
        return $ott;
    }
);

# Declare /debianregister route
sub init {
    my ($self) = @_;
    $self->addUnauthRoute( debianregister => 'register', ['POST'] );
    return 1;
}

sub check {
    my ( $self, $sub, $req ) = @_;

    # Launch getUser and intercept result
    my $res = $sub->($req);

    # If getUser succeeds, no need to do anything
    return PE_OK if $res == PE_OK;

    # USER NOT FOUND IN USERS DATABASE

    # Don't intercept DD requests
    return $res if $self->getModule( $req, "auth" ) eq 'LDAP';

    # Get linkedIn/GitHub data
    $self->p->setAuthSessionInfo($req);

    # Calculate macros
    $self->p->setMacros($req);

    # Display registration form
    return $self->p->sendHtml(
        $req,
        'debianRegistration',
        params => {
            USER  => $req->user,
            TOKEN => $self->ott->createToken(
                { user => $req->user, data => $req->sessionInfo }
            ),
        }
    );
}

# This method receives POST requests from registration form
sub register {
    my ( $self, $req ) = @_;

    # Objects inherited from LLNG libs (configured via manager:
    # "General Parameters" => "authentication modules"):
    #  * $self->dbh : SQL  connection (non DD users, registered using this plugin)
    #  * $self->ldap: LDAP connection (DD users)
}

1;
