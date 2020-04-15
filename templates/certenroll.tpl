<TMPL_INCLUDE NAME="header.tpl">
<main id="debianca" class="container">
  <div id="catitle" class="message message-positive alert">Debian SSO - enroll this browser</div>
  <div class="card">
    <form id="debform" method="post">
      <div class="form-group">
        <!-- TODO insert: CSRF token -->
        <p>
          <label for="id_validity">Validity:</label><br/>
          <input type="number" name="validity" value="365" required id="id_validity" /><br/>
          <small>Validity of the certificate in days (max 365)</small>
          <input id="token" type="hidden" name="token" value="<TMPL_VAR NAME="TOKEN">" />
        </p>
      </div>
      <div class="row">
        <div class="col-sm-6">
          <p>
            <label for="id_comment">Comment:</label><br>
            <textarea name="comment" cols="40" rows="10" id="id_comment"></textarea><br>
            <small>optional comment to identify this enrollment in the enrollment log (eg. hostname)</small>
          </p>
          <TMPL_IF NAME="LEVEL">
          <p><button id="getcert">Generate high level certificate</button></p>
          <TMPL_ELSE>
          <p><button id="getcert" class="btn btn-primary">Generate certificate</button></p>
          </TMPL_IF>
        </div>
        <div class="col-sm-6">
          <p>
            <label for="csr">Custom CSR</label><br/>
            <textarea id="csr" name="csr" cols="40" rows="10"></textarea>
          </p>
          <p><input type="submit" class="btn btn-primary" value="Post custom CSR"/></p>
        </div>
      </div>
    </form>

    <p>In case of problems, see the
      <a href="https://wiki.debian.org/DebianSingleSignOn">Wiki page</a>,
      especially <a href="https://wiki.debian.org/DebianSingleSignOn#Browser_support">browser support</a>,
      or try <a href="/debian/certs/enroll_csr/">getting a certificate manually</a>.
    </p>
  </div>
</main>
<div class="buttons">
  <a href="/certs/enrollSecure" class="btn btn-primary" role="button">
    <span class="fa fa-key"></span>
    <span>Get a high-level certificate <i>(DD only)</i></span>
  </a>
  <a href="/certs" class="btn btn-primary" role="button">
    <span class="fa fa-key"></span>
    <span>Back to certificate list</span>
  </a>
  <a id="goback" href="/" class="btn btn-primary" role="button">
    <span class="fa fa-home"></span>
    <span trspan="goToPortal">Go to portal</span>
  </a>
</div>
<script type="text/javascript" src="/static/debianca/pkijs/common.js"></script>
<script type="text/javascript" src="/static/debianca/pkijs/asn1.js"></script>
<script type="text/javascript" src="/static/debianca/pkijs/x509_schema.js"></script>
<script type="text/javascript" src="/static/debianca/pkijs/x509_simpl.js"></script>
<script type="text/javascript" src="/static/debianca/pkijs/pkcs12_simpl.js"></script>
<script type="text/javascript" src="/static/debianca/pkijs/pkcs12_schema.js"></script>
<script type="text/javascript" src="/static/debianca/pkijs/cms_simpl.js"></script>
<script type="text/javascript" src="/static/debianca/pkijs/cms_schema.js"></script>
<script type="text/javascript" src="/static/debianca/forge/forge.min.js"></script>
<script type="text/javascript" src="/static/debianca/minions.js"></script>
<script type="text/javascript" src="/static/debianca/pkcs12.js"></script>
<script type="text/javascript" src="/static/debianca/index.js"></script>
<TMPL_INCLUDE NAME="footer.tpl">
