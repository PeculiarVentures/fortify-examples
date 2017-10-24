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
function FillProviderSelect(domSelect) {
    return Promise.resolve()
        .then(function () {
            return ws.info()
                .then(function (info) {
                    for (let i = 0; i < info.providers.length; i++) {
                        const provider = info.providers[i];
                        // TODO: check provider.atr to filter pkcs#11 modules

                        const $option = document.createElement("option");
                        $option.setAttribute("value", provider.id);
                        $option.textContent = provider.name;
                        if (!i) {
                            // select first item
                            $option.setAttribute("selected", true);
                        }

                        domSelect.appendChild($option);
                    }
                })
        })
}

/**
 * Generates <option> for given <select> element
 * Gets list of certificate for provider. Shows only certificates which have private key
 * @param {*} crypto 
 * @param {*} domSelect 
 */
function fillCertificateSelect(provider, domSelect) {
    var certIDs, keyIDs;
    return Promise.resolve()
        .then(function () {
            return provider.isLoggedIn()
                .then(function (ok) {
                    if (!ok) {
                        return provider.login()
                            .catch(function (error) {
                                alert(error.message);
                            })
                    }
                });
        })
        .then(function () {
            return provider.certStorage.keys()
        })
        .then(function (indexes) {
            certIDs = indexes.filter(function (id) {
                var parts = id.split("-");
                return parts[0] === "x509";
            });
        })
        .then(function () {
            return provider.keyStorage.keys()
        })
        .then(function (indexes) {
            keyIDs = indexes.filter(function (id) {
                var parts = id.split("-");
                return parts[0] === "private";
            })
        })
        .then(function () {
            var promises = [];
            for (var i = 0; i < certIDs.length; i++) {
                (function () { // fix scope for promises
                    var certID = certIDs[i];
                    for (var j = 0; j < keyIDs.length; j++) {
                        var keyID = keyIDs[j];
                        if (keyID.split("-")[2] === certID.split("-")[2]) {
                            promises.push(
                                provider.certStorage.getItem(certID)
                                    .then(function (cert) {
                                        return {
                                            id: certID,
                                            item: cert,
                                        }
                                    })
                                    .catch(function (error) {
                                        console.error(error);
                                        return null
                                    })
                            );
                            break;
                        }
                    }
                })();
            }
            return Promise.all(promises);
        })
        .then(function (certs) {
            certs = certs.filter(function (item) { return !!item }); // skip 'null' results

            domSelect.textContent = "";

            return certs
                .map(function (cert) {
                    return {
                        id: cert.id,
                        name: GetCommonName(cert.item.subjectName),
                    }
                })
                .sort(function (a, b) {
                    if (a.name.toLowerCase() > b.name.toLowerCase()) {
                        return 1;
                    } else if (a.name.toLowerCase() < b.name.toLowerCase()) {
                        return -1
                    }
                    return 0;
                })
                .forEach(function (item, index) {
                    const $option = document.createElement("option");
                    $option.setAttribute("value", item.id);
                    $option.textContent = item.name;
                    if (!index) {
                        // select first item
                        $option.setAttribute("selected", true);
                    }

                    domSelect.appendChild($option);
                })

        })
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

function GetCertificateKey(type, provider, certID) {
    var certID;
    return Promise.resolve()
        .then(function () {
            return provider.keyStorage.keys()
        })
        .then(function (keyIDs) {
            for (var i = 0; i < keyIDs.length; i++) {
                var keyID = keyIDs[i];
                var parts = keyID.split("-");

                if (parts[0] === type && parts[2] === certID.split("-")[2]) {
                    return provider.keyStorage.getItem(keyID);
                }
            }
            return null;
        });
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