//**************************************************************************************
const Browser = {
  IE: "Internet Explorer",
  Safari: "Safari",
  Edge: "Edge",
  Chrome: "Chrome",
  Firefox: "Firefox Mozilla",
  Mobile: "Mobile",
};
//**************************************************************************************
function BrowserInfo() {
  const res = {
    name: "Unknown",
    version: "0"
  };

  const userAgent = self.navigator.userAgent;

  switch (true) {
    case (/edge\/([\d\.]+)/i.test(userAgent)):
      res.name = Browser.Edge;
      res.version = /edge\/([\d\.]+)/i.exec(userAgent)[1];
      break;
    case (/msie/i.test(userAgent)):
      res.name = Browser.IE;
      res.version = /msie ([\d\.]+)/i.exec(userAgent)[1];
      break;
    case (/Trident/i.test(userAgent)):
      res.name = Browser.IE;
      res.version = /rv:([\d\.]+)/i.exec(userAgent)[1];
      break;
    case (/chrome/i.test(userAgent)):
      res.name = Browser.Chrome;
      res.version = /chrome\/([\d\.]+)/i.exec(userAgent)[1];
      break;
    case (/mobile/i.test(userAgent) && /firefox/i.test(userAgent)):
      res.name = Browser.Mobile;
      res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
      break;
    case (/mobile/i.test(userAgent)):
      res.name = Browser.Mobile;
      res.version = /mobile\/([\w]+)/i.exec(userAgent)[1];
      break;
    case (/safari/i.test(userAgent)):
      res.name = Browser.Safari;
      res.version = /version\/([\d\.]+)/i.exec(userAgent)[1];
      break;
    case (/firefox/i.test(userAgent)):
      res.name = Browser.Firefox;
      res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
      break;
    default:
      console.log("UNKNOWN BROWSER");
  }

  return res;
}
//**************************************************************************************
function getRandomArbitrary(min, max) {
  return self.Math.random() * (max - min) + min;
}
//**************************************************************************************
function getRandomValues(buffer) {
  self.Math.seedrandom(self.location.href, { entropy: true });

  const buf = new Uint8Array(buffer.buffer);
  let i = 0;

  while (i < buf.length)
    buf[i++] = getRandomArbitrary(0, 255);

  return buffer;
}
//**************************************************************************************

const _self = self;
if (!(_self.crypto || _self.msCrypto)) {
  importScripts("//cdnjs.cloudflare.com/ajax/libs/seedrandom/2.4.0/seedrandom.min.js");
  _self.crypto = { getRandomValues: getRandomValues };
  Object.freeze(_self.crypto);
}

importScripts("/src/webcrypto-liner.shim.js?v=1");

switch (BrowserInfo().name) {
  case Browser.Edge:
  case Browser.Safari:
  case Browser.Mobile:
    importScripts("https://peculiarventures.github.io/pv-webcrypto-tests/src/asmcrypto.js");
    importScripts("https://peculiarventures.github.io/pv-webcrypto-tests/src/elliptic.js");
  default:
}

importScripts("https://cdn.rawgit.com/dcodeIO/protobuf.js/6.8.0/dist/protobuf.js");
importScripts("/src/webcrypto-socket.js");

//**************************************************************************************

async function main() {
  WebcryptoSocket.setEngine("liner", liner.crypto);

  self.ws = new WebcryptoSocket.SocketProvider({
    storage: await WebcryptoSocket.BrowserStorage.create(),
  });
  ws.connect("127.0.0.1:31337")
    .on("error", function (e) {
      console.error(e);
    })
    .on("listening", async (e) => {
      // Check if end-to-end session is approved
      if (! await ws.isLoggedIn()) {
        const pin = await ws.challenge();
        // show PIN
        setTimeout(() => {
          alert("2key session PIN:" + pin);
        }, 100)
        // ask to approve session
        await ws.login();
      }

      const info = await ws.info();
      const crypto = await ws.getCrypto(info.providers[0].id);
      console.log(await crypto.subtle.generateKey({ name: "AES-CBC", length: 128 }, true, ["encrypt"]));

      ws.cardReader
        .on("insert", (e) => console.log(e))
        .on("remove", (e) => console.log(e));
    });
}

main();