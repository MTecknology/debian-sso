<TMPL_INCLUDE NAME="header.tpl">
<main id="debregister" class="container">
  <TMPL_IF NAME="ERROR">
  <div id="msg" class="message message-negative alert"><TMPL_VAR NAME="ERROR"></div>
  <TMPL_ELSE>
  <div id="msg" class="message message-positive alert">Register to Debian</div>
  </TMPL_IF>
  <div class="card">
    <form id="registerform" method="post" action="/debianregister">
      <input id="token" type="hidden" name="token" value="<TMPL_VAR NAME="TOKEN">" />
      <div class="form-group">
        <label for="username">Debian username</label>
        <input class="form-control" name="username" id="username" aria-describedby=" usernameHelp"/>
        <small id=" usernameHelp" class="form-text text-muted">Choose your Debian nickname.</small>
      </div>
      <div class="form-group">
        <label for="displayname">displayname</label>
        <input class="form-control" name="displayname" id="displayname" aria-describedby=" displaynameHelp"/>
        <small id=" displaynameHelp" class="form-text text-muted">Choose your Debian nickname.</small>
      </div>
      <div class="form-group">
        <label for="firstname">firstname</label>
        <input class="form-control" name="firstname" id="firstname" aria-describedby=" firstnameHelp"/>
        <small id=" firstnameHelp" class="form-text text-muted">Choose your Debian nickname.</small>
      </div>
      <div class="form-group">
        <label for="lastname">lastname</label>
        <input class="form-control" name="lastname" id="lastname" aria-describedby=" lastnameHelp"/>
        <small id=" lastnameHelp" class="form-text text-muted">Choose your Debian nickname.</small>
      </div>
      <div class="form-group">
        <label for="gpgkey">gpgkey</label>
        <textarea class="form-control" name="gpgkey" id="gpgkey" aria-describedby=" gpgkeyHelp">
	</textarea>
        <small id=" gpgkeyHelp" class="form-text text-muted">Choose your Debian nickname.</small>
      </div>
      <div class="form-group">
        <label for="sshkey">sshkey</label>
        <textarea class="form-control" name="sshkey" id="sshkey" aria-describedby=" sshkeyHelp">
	</textarea>
        <small id=" sshkeyHelp" class="form-text text-muted">Choose your Debian nickname.</small>
      </div>
      <button id="submit" type="submit" class="btn btn-primary">Register me</button>
    </form>
  </div>
</main>
<script type="text/javascript" src="/static/debian/registration.js" />
<TMPL_INCLUDE NAME="footer.tpl">
