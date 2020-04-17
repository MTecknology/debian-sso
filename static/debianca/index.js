function populateAttr(cert, attr, value) {
    cert.addSubjectAttr(attr, value);
}

function pem2pkcs12(cert,key){
    let fCert = forge.pki.certificateFromPem(cert);
    let fKey = forge.pki.privateKeyFromPem(key);
    let password = prompt("Enter export password");
    let p12Asn1 = forge.pkcs12.toPkcs12Asn1(fKey, fCert, password,{algorithm:'3des'});
    // base64-encode p12
    let p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    return p12Der;
}

function downloadP12B64(name, p12b64) {
    var a = document.createElement('a');
    a.setAttribute('href', 'data:application/x-pkcs12;base64,' + p12b64);
    a.setAttribute('download', name);
    //a.appendChild(doc if (document.createEvent) {

    if (document.createEvent) {
        var event = document.createEvent('MouseEvents');
        event.initEvent('click', true, true);
        a.dispatchEvent(event);
    }
    else {
        a.click();
    }
}

$(document).ready(function() {

  // CSR generated by browser

  $('#getcert').on('click', function() {
    console.debug('generate keys');
    $('#getcert').prop('disabled', true);
    let pkcs10CSR = new org.pkijs.simpl.PKCS10();

    let publicKey;
    let privateKey;

    let hash_algorithm = "sha-512";
    let signature_algorithm_name = "RSASSA-PKCS1-V1_5"; // "RSA-PSS", "ECDSA"

    // WebCrypto
    let crypto = org.pkijs.getCrypto();
    if (typeof crypto == "undefined") {
        alert("No WebCrypto extension found");
        return;
    }

    pkcs10CSR.version = 0;
    pkcs10CSR.attributes = [];
    populateAttr(pkcs10CSR,'CN','yadd@debian.org');
    populateAttr(pkcs10CSR,'O','Debian');
    populateAttr(pkcs10CSR,'OU','Debian Developers');

    Promise.resolve().then(function () {
      let algorithm = org.pkijs.getAlgorithmParameters(signature_algorithm_name, "generatekey");
        if ("hash" in algorithm.algorithm) {
            algorithm.algorithm.hash.name = hash_algorithm;
        }
        return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    }).then(function (keyPair) {
        publicKey = keyPair.publicKey;
        privateKey = keyPair.privateKey;
    }).catch(function (error) {
        alert("Error during key generation: " + error);
    }).then(function () {
        return pkcs10CSR.subjectPublicKeyInfo.importKey(publicKey);
    }).then(function (result) {
        return crypto.digest({name: "SHA-1"}, pkcs10CSR.subjectPublicKeyInfo.subjectPublicKey.value_block.value_hex);
    }).then(function (result) {
        pkcs10CSR.attributes.push(new org.pkijs.simpl.ATTRIBUTE({
            type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
            values: [(new org.pkijs.simpl.EXTENSIONS({
                extensions_array: [
                    new org.pkijs.simpl.EXTENSION({
                        extnID: "2.5.29.14",
                        critical: false,
                        extnValue: (new org.pkijs.asn1.OCTETSTRING({value_hex: result})).toBER(false)
                    })
                ]
            })).toSchema()]
        }));
    }).then(function () {// Signing final PKCS#10 request
        return pkcs10CSR.sign(privateKey, hash_algorithm);
    }).catch(function (error) {
        alert("Error during exporting public key: " + error);
    }).then(function () {
        return crypto.exportKey("pkcs8", privateKey);
    }).then(function (pkcs8Privkey) {
        $.ajax('/certs/enroll', {
          dataType: 'json',
          type: 'POST',
          data: {
            csr: csr2pem(pkcs10CSR),
            token: $('#token').val(),
            comment: $('#id_comment').val(),
            validity: $('#id_validity').val(),
          },
          success: function(data) {
            if(data.result == 1) {
              let pem = data.cert;
              let p12Der = pem2pkcs12(pem,privkey2pem(pkcs8Privkey));
              let p12b64 = forge.util.encode64(p12Der);
              $('#catitle').html('Certificate generated');

              downloadP12B64('client.p12',p12b64);
            }
            else {
              console.error('Bad response',data);
            }
          },
          error: function(err) {
            console.error('Error: ', err);
            $('#catitle').html('An error happens, may be an expired token, try to reload this page');
            $('#catitle').removeClass('alert-success').addClass('alert-danger');
          },
        });
    }).catch(function (error) {
        alert("Error signing PKCS#10: " + error);
    });
    return false;
  });
})