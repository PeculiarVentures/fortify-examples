function errorCallback(e) {
  alert("Uncaught exception. See console logs for more details.")
}

self.addEventListener("error", errorCallback);
self.addEventListener("unhandledrejection", errorCallback);

/**
 * Select element by id
 * 
 * @param {string} id 
 * @returns 
 */
function $(id) {
  const result = document.getElementById(id);
  if (!result) {
    throw new Error("Cannot get element by id '" + id + "'");
  }
  return result;
}

/**
 * Generates <option> for given <select> element
 * Gets list of providers from Fortify
 * 
 * @param {Element} domSelect
 * @returns 
 */
async function FillProviderSelect(domSelect) {
  const info = await ws.info();
  let first = false;

  if (!info.providers.length) {
    const $option = document.createElement("option");
    $option.textContent = "No providers";
    $option.setAttribute("value", "");
    $option.setAttribute("disabled", true);
    $option.setAttribute("selected", true);
    domSelect.appendChild($option);
  }

  for (const provider of info.providers) {
    // TODO: check provider.atr to filter pkcs#11 modules

    const $option = document.createElement("option");
    $option.setAttribute("value", provider.id);
    $option.textContent = provider.name;
    if (!first) {
      // select first item
      $option.setAttribute("selected", true);
      first = true;
    }

    domSelect.appendChild($option);
  }
}

/**
 * Generates <option> for given <select> element
 * Gets list of certificate for provider. Shows only certificates which have private key
 * @param {*} crypto 
 * @param {*} domSelect 
 */
async function fillCertificateSelect(provider, domSelect) {
  if (! await provider.isLoggedIn()) {
    await provider.login();
  }

  let certIDs = await provider.certStorage.keys();
  certIDs = certIDs.filter((id) => {
    const parts = id.split("-");
    return parts[0] === "x509";
  });

  let keyIDs = await provider.keyStorage.keys()
  keyIDs = keyIDs.filter(function (id) {
    const parts = id.split("-");
    return parts[0] === "private";
  });

  const certs = [];
  for (const certID of certIDs) {
    for (const keyID of keyIDs) {
      if (keyID.split("-")[2] === certID.split("-")[2]) {
        try {
          const cert = await provider.certStorage.getItem(certID);

          certs.push({
            id: certID,
            item: cert,
          });
        } catch (e) {
          console.error(`Cannot get certificate ${certID} from CertificateStorage. ${e.message}`);
        }
      }
    }
  }

  domSelect.textContent = "";

  certs
    .map((cert) => {
      return {
        id: cert.id,
        name: GetCommonName(cert.item.subjectName),
      }
    })
    .sort((a, b) => {
      if (a.name.toLowerCase() > b.name.toLowerCase()) {
        return 1;
      } else if (a.name.toLowerCase() < b.name.toLowerCase()) {
        return -1
      }
      return 0;
    })
    .forEach((item, index) => {
      const $option = document.createElement("option");
      $option.setAttribute("value", item.id);
      $option.textContent = item.name;
      if (!index) {
        // select first item
        $option.setAttribute("selected", true);
      }

      domSelect.appendChild($option);
    });
}

/**
 * Converts DER to PEM
 * 
 * @param {BufferSource} buffer incoming DER
 * @param {string} name name for BEGIN | END blocks
 * @returns 
 */
function DerToPem(buffer, name) {
  let base64 = pvtsutils.Convert.ToBase64(buffer);

  const res = [];
  res.push("-----BEGIN " + name.toUpperCase() + "-----");
  while (base64.length > 64) {
    res.push(base64.substr(0, 64))
    base64 = base64.substr(64);
  }
  res.push(base64);
  res.push("-----END " + name.toUpperCase() + "-----");
  return res.join("\r\n");
}

/**
 * Converts PEM string to DER
 * 
 * @param {string} pemString PEM string
 * @returns 
 */
function PemToDer(pemString) {
  var b64 = pemString.replace(/-----([\w\d\s]+)-----/gi, "").replace(/\n/g, "").replace(/\r/g, "");
  var der = pvtsutils.Convert.FromBase64(b64);
  return der;
}

/**
 * Gets CommonName from normalized name of certificate
 * 
 * @param {any} name 
 * @returns 
 */
function GetCommonName(name) {
  var reg = /CN=(.+),?/i;
  var res = reg.exec(name);
  return res ? res[1] : "Unknown";
}

async function GetCertificateKey(type, provider, certID) {
  const keyIDs = await provider.keyStorage.keys()
  for (const keyID of keyIDs) {
    const parts = keyID.split("-");

    if (parts[0] === type && parts[2] === certID.split("-")[2]) {
      const key = await provider.keyStorage.getItem(keyID);
      if (key) {
        return key;
      }
    }
  }
  if (!key && type === "public") {
    const cert = await provider.certStorage.getItem(certID);
    return cert.publicKey;
  }
  return null;
}

/**
 * Fix RDNs for PKIjs.
 * `RDNs = [RDN[attr],RDN[attr],...]`
 * @param {any} name 
 */
function fixDN(name) {
  if (name.typesAndValues) {
    const schema = (new asn1js.Sequence({
      value: name.typesAndValues.map(function (element) {
        return new asn1js.Set({
          value: [element.toSchema()]
        })
      })
    }));
    const der = schema.toBER()
    name.fromSchema(asn1js.fromBER(der).result);
  }
}