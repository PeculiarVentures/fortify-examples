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
        .then(function() {
            return ws.info()
                .then(function(info) {
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
    const b64 = pemString.replace(/-----([\w\d\s]+)-----/gi, "").replace(/\n/g, "").replace(/\r/g, "");
    const der = pvtsutils.Convert.FromBase64(b64);
    return der;
}

/**
 * Gets CommonName from normalized name of certificate
 * 
 * @param {any} name 
 * @returns 
 */
function GetCommonName(name) {
    const reg = /CN=([\w\d\s]+)/i;
    const res = reg.exec(name);
    return  res ? res[1] : "Unknown";
}
