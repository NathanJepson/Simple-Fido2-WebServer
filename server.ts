import { DB } from "https://deno.land/x/sqlite/mod.ts";
import { Fido2Lib} from "https://deno.land/x/fido2/dist/main.js";

const f2l = new Fido2Lib({
    timeout: 42,
    rpId: "localhost",
    rpName: "Fido Implementation Nathan",
    rpIcon: "http://localhost:8000/favicon.ico",
    challengeSize: 128,
    attestation: "none", // The preferred attestation type to be used. See [AttestationConveyancePreference]
    // {https://w3.org/TR/webauthn/#enumdef-attestationconveyancepreference} in the WebAuthn spec
    cryptoParams: [-7, -257],
    authenticatorAttachment: "cross-platform", //cross-platform is roaming, platform is OS
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "required"
});

function generateUserId() {
  // 32 random bytes (safe within 1–64 bytes range)
  return crypto.getRandomValues(new Uint8Array(32));
}

function toBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bufferSourceToBase64Url(buf: BufferSource): string {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  const bin = String.fromCharCode(...bytes);
  return btoa(bin)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlToUint8Array(base64url: string) {
    // Replace - with + and _ with / and pad with =
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }

    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function prepareRegistrationOptionsForClient(options: PublicKeyCredentialCreationOptions) {
  return {
    ...options,
    challenge: bufferSourceToBase64Url(options.challenge),
    user: {
      ...options.user,
      id: bufferSourceToBase64Url(options.user.id),
    },
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      ...cred,
      id: bufferSourceToBase64Url(cred.id),
    })),
  };
}

function prepareAuthenticationOptionsForClient(options: PublicKeyCredentialRequestOptions) {
  return {
    ...options,
    challenge: bufferSourceToBase64Url(options.challenge),
  };
}

// Function to read and serve the HTML file
const serveHtml = async (): Promise<string> => {
  // Read the HTML file from the filesystem (ensure the correct path)
  const htmlContent = await Deno.readTextFile("./basic.html");
  return htmlContent;
};

const serveHtmlRegister = async (): Promise<string> => {
  // Read the HTML file from the filesystem (ensure the correct path)
  const htmlContent = await Deno.readTextFile("./register.html");
  return htmlContent;
};

/*
const serveHTMLIndex = async (): Promise<string> => {
  const htmlContent = await Deno.readTextFile("./Box/index.html");
  return htmlContent;
}
*/

const servePNG = async (): Promise<Uint8Array> => {
  const htmlContent = await Deno.readFile("./Box/Service.png");
  return htmlContent;
}

const serveICO = async (): Promise<Uint8Array> => {
  const Content = await Deno.readFile("./favicon.ico");
  return Content;
}

async function hash(message: string | undefined) {
  const data = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
  return hashHex
}

function checkSessionExists(db : DB, cookie : string) {
  try {
    const query = db.prepareQuery("SELECT id FROM cookies WHERE cookie = ?");
    const row = query.first([cookie]);
    if (row === undefined) {
      return false
    } else {
      return true
    }
  } catch (error) {
    throw error
  }
}

// Define the server using Deno.serve()
Deno.serve(async (req) => {

  const db = new DB("./test.db");
  const pathname = new URL(req.url).pathname;

  const cookieHeader = req.headers.get("Cookie");

  // Parse cookies into an object with a specific type
  const cookies: { [key: string]: string } = cookieHeader
    ? cookieHeader.split(";").reduce((acc: { [key: string]: string }, cookie) => {
        const [key, value] = cookie.trim().split("=");
        acc[key] = value;
        return acc;
      }, {})
    : {};

  // Access the session_id cookie
  const sessionId = cookies["session_id"];

  if (req.method === "GET" && pathname === "/") {
    try {
      // Serve the HTML page
      const htmlContent = await serveHtml();
      return new Response(htmlContent, {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    } catch (error) {
      console.error("Error serving HTML:", error);
      return new Response("Internal Server Error", { status: 500 });
    }
  }

  if (req.method === "GET" && pathname ==="/favicon.ico") {
    try {
      const ico = await serveICO();
      return new Response(ico, {
        status: 200,
        headers: { "Content-Type": "image/ico" },
      });
    } catch (error) {
      console.error("Error serving favicon:",error);
      return new Response(
        JSON.stringify({ error: "Internal Server Error" }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  if (req.method === "GET" && pathname === "/register") {
    try {
      // Serve the HTML page
      const htmlContent = await serveHtmlRegister();
      return new Response(htmlContent, {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    } catch (error) {
      console.error("Error serving HTML:", error);
      return new Response("Internal Server Error", { status: 500 });
    }
  }

  if (req.method === "POST" && pathname === "/submit") {

    try {
      // Parse JSON body from the POST request
      const body = await req.json();

      // Log the data (for demonstration purposes)
      console.log("Received data:", body);

      try {
        // We check if there is such a user in the database
        const query = db.prepareQuery("SELECT id FROM people WHERE username = ?");
        const row = query.first([body.username]);
        console.log("Data in db:",row);

        if (row === undefined) {
          return new Response(
            JSON.stringify({ message: "Login Failure!" }),
            { status: 401, headers: { "Content-Type": "application/json" } }
          );
        } else {

          const password = body.password;
          const hashQuery = db.prepareQuery("SELECT password_hash FROM people WHERE username = ?");
          const hashRow = hashQuery.first([body.username]);
          const provided_hash = await hash(password);

          if (hashRow === undefined) {
            console.log("Race condition or entry disappeared.")
            return new Response(
              JSON.stringify({ error: "Internal Server Error" }),
              { status: 500, headers: { "Content-Type": "application/json" } }
            );
          }

          console.log("Provided hash", provided_hash)
          console.log("Actual hash", hashRow[0])

          if (provided_hash === hashRow[0]) {
            // Create new session cookie
            const newCookie = crypto.randomUUID();
            db.query("INSERT INTO cookies (cookie,id) VALUES (?,?)", [newCookie,String(row[0])]);
            console.log("Cookie we are sending:",newCookie)
            
            // Respond with a success message
            return new Response(
              JSON.stringify({ message: "Data received successfully!"}),
              { status: 200, headers: { "Content-Type": "application/json", 
                "Set-Cookie":`session_id=${newCookie}; path=/; HttpOnly; SameSite=Strict; Max-Age=3600`} 
              }
            );
          } else {
            return new Response(
            JSON.stringify({ message: "Login Failure!" }),
              { status: 401, headers: { "Content-Type": "application/json" } }
            );
          }
        } 
      } catch (error) {
        console.error("Internal Server Error", error);
        return new Response(
          JSON.stringify({ error: "Internal Server Error" }),
          { status: 500, headers: { "Content-Type": "application/json" } }
        );
      }
    } catch (error) {
      console.error("Error parsing JSON:", error);
      return new Response(
        JSON.stringify({ error: "Invalid JSON format" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  if (req.method === "POST" && pathname === "/register") {
    try {
      // Parse JSON body from the POST request
      const body = await req.json();

      // Log the data (for demonstration purposes)
      console.log("New user data:", body);

      try {
        // We check if there is such a user in the database
        const query = db.prepareQuery("SELECT id FROM people WHERE username = ?");
        const username = body.username;
        const row = query.first([username]);
        if (row === undefined) {
          const password_hash = await hash(body.password);
          console.log("Hash:", password_hash);
          db.query("INSERT INTO people (id,username,password_hash) VALUES (?,?)", [bufferSourceToBase64Url(generateUserId()),username,password_hash]);
          return new Response(
            JSON.stringify({ message: `Successfully registered new user ${username}` }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        } else {
          console.error(`User ${username} already exists.`);
          return new Response(
            JSON.stringify({ error: "User already exists." }),
            { status: 409, headers: { "Content-Type": "application/json" } }
          );
        }
      } catch (error) {
        console.error("SQLite error:", error);
        return new Response(
          JSON.stringify({ error: "Internal Server Error" }),
          { status: 500, headers: { "Content-Type": "application/json" } }
        );
      }
    } catch (error) {
      console.error("Error parsing JSON:", error);
      return new Response(
        JSON.stringify({ error: "Invalid JSON format" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  if (req.method === "POST" && pathname === "/registerFido2options") {
    
    const registrationOptions = await f2l.attestationOptions() as PublicKeyCredentialCreationOptions;

    try {
      const body = await req.json();
      // Log the data (for demonstration purposes)
      console.log("New user data:", body);
      const username = body.username;
      
      try {
        // We check if there is such a user in the database
        const query = db.prepareQuery("SELECT id FROM people WHERE username = ?");
        const row = query.first([username]);

        const uniqueID = generateUserId()

        //TODO: If there's no Fido2 Credentials on the user entry -- or a password hash -- we can safely delete the user 
        //in the database and proceed with registering

        if (row === undefined) {
            const user = {
                id: uniqueID,
                name: username,
                displayName: "Example User"
            };
                
            registrationOptions.user = user;

            //console.log('Registration options',registrationOptions)

          try {
            //registrationOptions.challenge = toBase64Url(registrationOptions.challenge);
            const encodedChallenge = bufferSourceToBase64Url(registrationOptions.challenge);
            //console.log("Challenge type:",typeof registrationOptions.challenge);
            //registrationOptions.challenge = Buffer.from(registrationOptions.challenge);
            
            //console.log('Check registration options challenge type',registrationOptions.challenge);
            //console.log("Challenge type:",typeof registrationOptions.challenge);
            //console.log('Params before inserting session challenge',username,encodedChallenge);
            db.query("INSERT INTO people (id,username) VALUES (?,?)", [bufferSourceToBase64Url(registrationOptions.user.id),username]);
            db.query("INSERT INTO sessionChallenges (username,sessionChallenge) VALUES (?,?)", [username,encodedChallenge]);            
            const safeOptions = prepareRegistrationOptionsForClient(registrationOptions);

            try {
              return new Response(JSON.stringify(safeOptions), {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                },
              }); }
              catch (error) {
                console.error("JSON error:", error);
                return new Response(
                  JSON.stringify({ error: "Internal Server Error" }),
                  { status: 500, headers: { "Content-Type": "application/json" } }
                );
              }

          } catch (error) {
              console.error("SQLite error:", error);
              return new Response(
                JSON.stringify({ error: "Internal Server Error" }),
                { status: 500, headers: { "Content-Type": "application/json" } }
              );
          }
        } else {
          console.error(`User ${username} already exists.`);
          return new Response(
            JSON.stringify({ error: "User already exists." }),
            { status: 409, headers: { "Content-Type": "application/json" } }
          );
        }
      } catch (error) {
        console.error("SQLite error:", error);
        return new Response(
          JSON.stringify({ error: "Internal Server Error" }),
          { status: 500, headers: { "Content-Type": "application/json" } }
        );
      }
      
    } catch (error) {
      console.error("Error parsing JSON:", error);
      return new Response(
        JSON.stringify({ error: "Invalid JSON format" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  if (req.method === "POST" && pathname === "/registerFido2") {
         
    try {
      const clientAttestationResponse = await req.json();  
      console.log(clientAttestationResponse);

      // Let's decode the clientDataJSON to get more info
      const clientDataJSON = JSON.parse(atob(clientAttestationResponse.response.clientDataJSON.replace(/-/g, '+').replace(/_/g, '/')));
      console.log("Decoded client data:", clientDataJSON);

      try {
        const username = clientAttestationResponse.username;

        const query2 = db.prepareQuery("SELECT sessionChallenge FROM sessionChallenges WHERE username = ?");
        const challengeRow = query2.first([username]);

        if (!challengeRow) {
          console.error("Session challenge does not exist");
          return new Response(
            JSON.stringify({ error: "Invalid registration information." }),
            { status: 400, headers: { "Content-Type": "application/json" } }
          );
        }

        const sessionChallenge = challengeRow[0];

        const expectations = {
          challenge: sessionChallenge,
          origin: "http://localhost:8000",
          factor: "either" as const
        };

        console.log("Expectations:", expectations);
        console.log("Challenge from client data:", clientDataJSON.challenge);
        console.log("Expected challenge:", sessionChallenge);

        try {
          //clientAttestationResponse.id = base64urlToUint8Array(clientAttestationResponse.id).buffer;
          //clientAttestationResponse.rawId = base64urlToUint8Array(clientAttestationResponse.rawId).buffer;
          //clientAttestationResponse.rawId = base64urlToUint8Array(clientAttestationResponse.rawId).buffer;

          //clientAttestationResponse.response.attestationObject = base64urlToUint8Array(clientAttestationResponse.response.attestationObject).buffer;
          //clientAttestationResponse.response.clientDataJSON = base64urlToUint8Array(clientAttestationResponse.response.clientDataJSON).buffer;
          
          const attestationResult = {
            id: base64urlToUint8Array(clientAttestationResponse.rawId).buffer,
            rawId: base64urlToUint8Array(clientAttestationResponse.rawId).buffer,
            response: {
              attestationObject: clientAttestationResponse.response.attestationObject,
              clientDataJSON: clientAttestationResponse.response.clientDataJSON
            }
          };
          
          const regResult = await f2l.attestationResult(attestationResult, expectations); // will throw on error
          console.log("Registration result:", regResult);

          // Save regResult.authnrData.get("credentialPublicKeyPem") and counter
          if (regResult.authnrData?.get('credentialPublicKeyPem') !== undefined && regResult.authnrData?.get('counter') !== undefined && regResult.authnrData?.get('credId') !== undefined) {
            console.log("Registration result:", regResult);

            const credId = toBase64Url(regResult.authnrData.get('credId'));
            //const publicKey = toBase64Url(regResult.authnrData.get('credentialPublicKeyCose'));
            const publicKey = regResult.authnrData.get('credentialPublicKeyPem');
            const counter = regResult.authnrData.get('counter');

            try {
              db.query("INSERT INTO credentials (username, cred_id, public_key, counter) VALUES (?, ?, ?, ?)",[username, credId, publicKey, counter]);
              
              // Clean up the session challenge
              db.query("DELETE FROM sessionChallenges WHERE username = ?", [username]);
              
              return new Response(
                  JSON.stringify({ success: true, message: `Successfully registered new user ${username}` }),
                  { status: 200, headers: { "Content-Type": "application/json" } }
              );
            } catch (error) {
                console.error("SQLite error:", error);
                return new Response(
                  JSON.stringify({ error: "Internal Server Error" }),
                  { status: 500, headers: { "Content-Type": "application/json" } }
                );
              }
          } else {
            throw "Result of regResult is empty, or properties of authnrData have changed.";
          }
        } catch (error) {
          console.error("Error registering credentials:", error);
          return new Response(
            JSON.stringify({ error: "Invalid registration information." }),
            { status: 400, headers: { "Content-Type": "application/json" } }
          );
        }
      } catch (error) {
          console.error("SQLite error:", error);
          return new Response(
            JSON.stringify({ error: "Internal Server Error" }),
            { status: 500, headers: { "Content-Type": "application/json" } }
          );
      }
    } catch (error) {
      console.error("Error parsing JSON:", error);
      return new Response(
        JSON.stringify({ error: "Invalid JSON format" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  if (req.method === "POST" && pathname === "/Fido2-Begin") {

     try {
      const userRequest = await req.json();  
      console.log('Fido2 auth begin user request:',userRequest);
      
      try {
        const authnOptions = await f2l.assertionOptions() as PublicKeyCredentialRequestOptions;
        if (authnOptions) {
          try {
            console.log("New Fido2 login request:", userRequest);

            const username = userRequest.username;

            const query3 = db.prepareQuery("SELECT cred_id FROM credentials WHERE username = ?");
            const credIDRow = query3.first([username]);

            if (!credIDRow) {
              console.error("Fido2 credentials don't exist for",username);
              return new Response(
                JSON.stringify({ error: "Invalid login information." }),
                { status: 400, headers: { "Content-Type": "application/json" } }
              );
            } else {

              const credId = credIDRow[0];
              const encodedChallenge = bufferSourceToBase64Url(authnOptions.challenge);
              const safeAuthnOptions = prepareAuthenticationOptionsForClient(authnOptions);

              const safeAuthnOptions2 = {
                  allowCredentials: [ // force only specific credentials
                    {
                      id: credId,
                      type: "public-key",
                    },
                  ],
                  ...safeAuthnOptions,
              };
              console.log('Sending authnOptions to user:',safeAuthnOptions2);
              return new Response(JSON.stringify(safeAuthnOptions2), {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                }
              });
            }

          } catch (error) {
          console.error("SQLite error:", error);
          return new Response(
            JSON.stringify({ error: "Internal Server Error" }),
            { status: 500, headers: { "Content-Type": "application/json" } }
          );
        }

        } else {
          console.error("Error in instantiating authnOptions");
          return new Response(
            JSON.stringify({ error: "Internal Server Error" }),
            { status: 500, headers: { "Content-Type": "application/json" } }
          );
        }

      } catch (error) {
          console.error("Error:", error);
          return new Response(
            JSON.stringify({ error: "Internal Server Error" }),
            { status: 500, headers: { "Content-Type": "application/json" } }
          );
      }

     } catch (error) {
      console.error("Error parsing JSON:", error);
      return new Response(
        JSON.stringify({ error: "Invalid JSON format" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }
  }


  if (req.method === "POST" && pathname === "/Fido2") {
    
  }

  if (req.method === "GET" && pathname.substring(0,4) === "/Box") {

    console.log("Service.png queried");
    
    if (pathname.substring(4) === "/Service.png") {
      try {
        // Serve the HTML page
        console.log("cookie header is:",String(cookieHeader))
        console.log("Session ID is:",sessionId);

        if (sessionId === undefined) {
          //Forbidden
          console.log("Session does not exist!")
          return new Response(
            JSON.stringify({ message: "Forbidden!" }),
              { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }

        if (checkSessionExists(db,sessionId)) {
          //Serve Box/index.html if session cookie exists
          console.log("Session exists!")
          const png = await servePNG();
          return new Response(png, {
            status: 200,
            headers: { "Content-Type": "image/png" },
          });
        } else {
          //Forbidden
          console.log("Session does not exist!")
          return new Response(
            JSON.stringify({ message: "Forbidden!" }),
              { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }
      } catch (error) {
        console.error("Error serving HTML:", error);
        return new Response("Internal Server Error", { status: 500 });
      }
    } else {
      return new Response("404 Not Found", { status: 404 });
    }
  }
  // Handle other methods or URLs (404 Not Found)
  return new Response("404 Not Found", { status: 404 });
});