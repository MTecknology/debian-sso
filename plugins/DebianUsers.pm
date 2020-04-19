# Plugin to register authenticated users (GitHub, LinkedIn,...) but not known
# by our SQL database

package Lemonldap::NG::Portal::Plugins::DebianUsers;

use strict;

use Moo;

extends 'Lemonldap::NG::Portal::Main::Plugin',
  'Lemonldap::NG::Portal::Lib::DBI',
  'Lemonldap::NG::Portal::Lib::LDAP';

use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_INFO
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

# SQL fields
# * uid: nickname
# * displayname: display name
# * sshkey: SSK key
# * gpgkey: GPG key
our @fields = (qw(uid displayname sshkey gpgkey));

# Sessions parameter: this plugin uses macros that returns wanted data:
#  * mail: should be
#    `($uid ? "$uid\@debian.org" : $linkedIn_emailAddress ? $linkedIn_emailAddress : $github_emailAddress )`

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
    return $self->form($req);
}

# This method receives POST requests from registration form
sub register {
    my ( $self, $req ) = @_;

    # Objects inherited from LLNG libs (configured via manager:
    # "General Parameters" => "authentication modules"):
    #  * $self->dbh : SQL  connection (non DD users, registered using this
    #                 plugin)
    #  * $self->ldap: LDAP connection (DD users)

    # 0 - get data
    my $nickname = $req->param('nick');
    my $token    = $req->param('token');

    # 1 - check token
    my $session = $self->ott->getToken($token);
    unless ($session) {
        return $self->sendError( $req,
            'Bad token or token expired, restart registration process', 400 );
    }
    $req->user( $session->{user} );
    $req->sessionInfo( $session->{data} );

    # 2 - verify that nickname does not already exist in LDAP or SQL DB
    my $res = eval { $self->_checknickname($nickname) };
    if ($@) {
          return $self->p->sendError( $req, 'LDAP server seems down', 500 );
    }

    # 2.1 - case OK (nickname not used)
    if ($res) {
          return $self->_registerUser($req);
    }

    # 2.2 - case NOK, display form
    else {
          if ( $req->wantJSON ) {
              return $self->p->sendJSONresponse(
                  $req,
                  {
                      result => 0,
                      error  => 'Nickname exists already, choose another one'
                  }
              );
          }
          else {
              return $self->form( $req,
                  'Nickname exists already, choose another one' );
        }
    }
}

# Populate and display form
sub form {
      my ( $self, $req, $error ) = @_;
      return $self->p->sendHtml(
          $req,
          'debianRegistration',
          params => {
              USER  => $req->user,
              TOKEN => $self->ott->createToken(
                  { user => $req->user, data => $req->sessionInfo }
              ),
              ERROR => $error,
          }
      );
}

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
          $self->logger->error( 'LDAP returns an error: ' . $mesg->error );
          die;
      }

      # Fail if a DD exists with this nickname
      return 0 if $mesg->entry(0);
}

sub _registerUser {
      my ( $self, $req ) = @_;
      eval {
          $self->dbh->prepare( 'INSERT INTO '
                . $self->table
                . ' VALUES ('
                . join( ',', map { '?' } @fields )
                . ')' );
          $self->dbh->execute( map { $req->param($_) } @fields );
      };
      if ($@) {

          # If connection isn't available, error is displayed by dbh()
          $self->logger->error("DBI error: $@") if ( $self->_dbh );
          return $self->p->sendError( $req, 'Error form database, try later' );
      }

      # Finish auth process
      $req->info('Successfully registered');
      return $self->p->do(
          $req,
          @{ $self->p->betweenAuthAndData },
          $self->p->sessionData,
          @{ $self->p->afterData },
          $self->p->validSession,
          @{ $self->p->endAuth },
          sub { PE_INFO },
      );
}

1;
