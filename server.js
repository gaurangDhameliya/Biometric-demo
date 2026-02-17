/**
 * SIMPLEWEBAUTHN — BIOMETRIC / FACEID LOGIN DEMO
 * ------------------------------------------------
 * Single file Node.js server
 * Registration + Authentication
 * Uses platform authenticators (FaceID, TouchID, Windows Hello)
 *
 * Run:
 *   npm install express express-session @simplewebauthn/server
 *   node server.js
 */

import express from "express";
import session from "express-session";
import crypto from "crypto";
import cors from "cors";

/**
 * SimpleWebAuthn server functions
 */
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const app = express();

/**
 * Parse JSON body
 */
app.use(express.json());

app.use(
  cors({
    origin: "http://localhost:3000", // frontend
    credentials: true,               // allow cookies
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);

/**
 * Session middleware
 * We store challenges here temporarily
 */
app.use(
  session({
    secret: "super-secret-demo-key",
    resave: false,
    saveUninitialized: true,
     cookie: {
      httpOnly: true,
      sameSite: "lax",   // IMPORTANT
      secure: false,     // true only for HTTPS
    },
  })
);

/**
 * ---------------------------------------------------------
 * DEMO DATABASE (IN MEMORY)
 * ---------------------------------------------------------
 * Replace with real DB in production
 *
 * Structure:
 * users = {
 *   username: {
 *     id,
 *     username,
 *     credentials: [
 *       {
 *         credentialID,
 *         publicKey,
 *         counter
 *       }
 *     ]
 *   }
 * }
 */
const users = new Map();

/**
 * =========================================================
 * 1️⃣ REGISTRATION — GENERATE OPTIONS
 * =========================================================
 *
 * Client calls this before biometric prompt appears
 */
app.post("/register/options", async(req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).send("Username required");
  }

  /**
   * Create or fetch user
   */
  let user = users.get(username);

  if (!user) {
    user = {
      id: crypto.randomUUID(),
      username,
      credentials: [],
    };

    users.set(username, user);
    console.log("🚀 ~ users:", users);
  }

  /**
   * Generate WebAuthn registration options
   */
  const options =await generateRegistrationOptions({
    rpName: "Juno Markets",
    /**
     * MUST match your domain in production
     */
    rpID: "7cxjtdbw-4000.inc1.devtunnels.ms",
    userID: Buffer.from(user.id),
    userName: user.username,

    /**
     * We don’t need attestation for most apps
     */
    attestationType: "none",

    /**
     * Restrict to platform authenticators
     * → FaceID / TouchID / Windows Hello
     */
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required",
    },
  });

  /**
   * Store challenge in session
   * We verify it later
   */
  console.log("OPTIONS:", options);

  req.session.challenge = options.challenge;
  req.session.username = username;

  res.json(options);
});

/**
 * =========================================================
 * 2️⃣ REGISTRATION — VERIFY RESPONSE
 * =========================================================
 *
 * Client sends biometric result here
 */
app.post("/register/verify", async (req, res) => {
  const body = req.body;

  const username = req.session.username;
  const expectedChallenge = req.session.challenge;

  const user = users.get(username);

  if (!user) {
    return res.status(400).send("User not found");
  }

  try {
    /**
     * Verify registration response
     */
    const verification = await verifyRegistrationResponse({
      response: body,

      expectedChallenge,

      /**
       * MUST match frontend origin
       */
      expectedOrigin: "http://localhost:3000",

      /**
       * MUST match rpID
       */
      expectedRPID: "localhost",
    });

    if (verification.verified) {
      /**
       * Extract credential info
       */
      const {
        credentialPublicKey,
        credentialID,
        counter,
      } = verification.registrationInfo;

      /**
       * Store credential
       */
      user.credentials.push({
        credentialID,
        publicKey: credentialPublicKey,
        counter,
      });
    }

    res.json({
      verified: verification.verified,
    });
  } catch (error) {
    console.error(error);
    res.status(400).send(error.message);
  }
});

/**
 * =========================================================
 * 3️⃣ LOGIN — GENERATE AUTH OPTIONS
 * =========================================================
 */
app.post("/login/options", (req, res) => {
  const { username } = req.body;

  const user = users.get(username);

  if (!user) {
    return res.status(404).send("User not found");
  }

  /**
   * Generate authentication options
   */
  const options = generateAuthenticationOptions({
    rpID: "localhost",

    /**
     * Require biometric verification
     */
    userVerification: "required",

    /**
     * Allow only this user's credentials
     */
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.credentialID,
      type: "public-key",
    })),
  });

  /**
   * Store challenge for verification
   */
  req.session.challenge = options.challenge;
  req.session.username = username;

  res.json(options);
});

/**
 * =========================================================
 * 4️⃣ LOGIN — VERIFY AUTH RESPONSE
 * =========================================================
 */
app.post("/login/verify", async (req, res) => {
  const body = req.body;

  const username = req.session.username;
  const expectedChallenge = req.session.challenge;

  const user = users.get(username);

  if (!user) {
    return res.status(400).send("User not found");
  }

  /**
   * Find credential used
   */
  const credential = user.credentials.find(
    (c) => c.credentialID.toString() === body.id
  );

  if (!credential) {
    return res.status(400).send("Credential not registered");
  }

  try {
    /**
     * Verify authentication response
     */
    const verification = await verifyAuthenticationResponse({
      response: body,

      expectedChallenge,
      expectedOrigin: "http://localhost:3000",
      expectedRPID: "localhost",

      authenticator: {
        credentialID: credential.credentialID,
        credentialPublicKey: credential.publicKey,
        counter: credential.counter,
      },
    });

    if (verification.verified) {
      /**
       * Update counter (prevents replay attacks)
       */
      credential.counter =
        verification.authenticationInfo.newCounter;
    }

    res.json({
      verified: verification.verified,
    });
  } catch (error) {
    console.error(error);
    res.status(400).send(error.message);
  }
});

/**
 * =========================================================
 * START SERVER
 * =========================================================
 */
app.listen(4000, () => {
  console.log("🚀 Server running on http://localhost:4000");
});