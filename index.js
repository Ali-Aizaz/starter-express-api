const express = require("express");
const app = express();
const bodyparser = require("body-parser");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

class ErrorResponse extends Error {
  constructor(message, errorCode) {
    super(message);
    this.message = message;
    this.code = errorCode;
    Error.captureStackTrace(this, this.constructor);
  }
}

app.use(bodyparser.json({ limit: "50mb" }));

const appleLogin = async (req, res, next) => {
  const { provider, response } = req.body;
  if (provider === "apple") {
    //validate apple signin
    const { identityToken, user } = response.response;
    const jwToken = jwt.decoded(identityToken, { complete: true });
    const kid = jwToken.header.kid;

    const appleKey = await getAppleSigninKey(kid);
    if (!appleKey) {
      return next(new ErrorResponse("Apple Server Error", 500));
    }

    const payload = await verifyJWT(identityToken, appleKey);
    if (!payload) {
      return next(new ErrorResponse("Apple Server Error", 500));
    }
    res.status(200).json({ "Sign in with apple success ": payload });
  } else {
    res.json({ message: "Unauthorized Provider" });
  }
};

const verifyJWT = (token, appleKey) => {
  return new Promise((resolve) => {
    jwt.verify(token, appleKey, (err, payload) => {
      if (err) {
        console.error(err);
        return resolve(null);
      }
      resolve(payload);
    });
  });
};

const client = jwksClient({
  jwksUri: "https://appleid.apple.com/auth/keys",
});

//gets the public key from apple
const getAppleSigninKey = (kid) => {
  return new Promise((resolve) => {
    client.getSigningKey(kid, (err, key) => {
      if (err) {
        console.error(err);
        return resolve(null);
      }
      const signingKey = key.getPublicKey();
      resolve(signingKey);
    });
  });
};

app.all("/", (req, res) => {
  console.log("Just got a request!");
  res.send("Yo Ali Bro!");
});

app.post("/testPost", (req, res, next) => {
  res.status(200).json({ success: true, message: "Working post request" });
});

app.post("/auth", appleLogin);

app.listen(process.env.PORT || 8080);
