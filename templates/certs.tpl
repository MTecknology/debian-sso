<TMPL_INCLUDE NAME="header.tpl">
<main id="debianca" class="container">
  <div class="message message-positive alert">Your Debian SSO certificates</div>
  <div class="card">
    <div class="row">
      <TMPL_LOOP NAME="CERTS">
        <div class="col-sm">
          <form method="POST" class="form-group">
          <input type="hidden" name="serial" value="<TMPL_VAR NAME="serial">" />
          <table>
            <tbody>
              <tr><td><TMPL_VAR NAME="serial"></td></tr>
              <TMPL_IF NAME="expired">
              <tr><th>EXPIRED</th></tr>
              <TMPL_ELSE>
              <tr><td><TMPL_VAR NAME="expires"></td></tr>
              </TMPL_IF>
              <tr><td><TMPL_VAR NAME="comment"></td></tr>
	      <TMPL_IF NAME="highLevel">
	      <tr><td>High level</td></tr>
	      </TMPL_IF>
            </tbody>
          </table>
          <input type="submit" class="btn btn-primary" value="Revoke this certificate" />
          </form>
        </div>
      </TMPL_LOOP>
    </div>
  </div>
</main>
<div class="buttons">
  <a href="/certs/enroll" class="btn btn-primary" role="button">
    <span class="fa fa-key"></span>
    <span>Add a certificate</span>
  </a>
  <a id="goback" href="/" class="btn btn-primary" role="button">
    <span class="fa fa-home"></span>
    <span trspan="goToPortal">Go to portal</span>
  </a>
</div>
<TMPL_INCLUDE NAME="footer.tpl">
