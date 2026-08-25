function base64url(input) {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64urlToBytes(input) {
  input = input.replace(/-/g, "+").replace(/_/g, "/");

  while (input.length % 4) {
    input += "=";
  }

  const binary = atob(input);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function decodeJwtPart(part) {
  const bytes = base64urlToBytes(part);
  return JSON.parse(new TextDecoder().decode(bytes));
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const payload = {
    iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  const privateKey = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n");

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privateKey),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(unsignedToken)
  );

  const signatureString = String.fromCharCode(
    ...new Uint8Array(signature)
  );

  const jwt = `${unsignedToken}.${base64url(signatureString)}`;

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type:
          "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwt
      })
    }
  );

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      "Google authentication failed: " +
        JSON.stringify(result)
    );
  }

  return result.access_token;
}

async function verifyCloudflareAccess(request, env) {
  const token =
    request.headers.get("Cf-Access-Jwt-Assertion");

  if (!token) {
    throw new Error("Brak tokenu Cloudflare Access.");
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error("Nieprawidłowy token Cloudflare Access.");
  }

  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);

  const teamDomain = String(env.TEAM_DOMAIN || "")
    .replace(/\/+$/, "");

  const certsResponse = await fetch(
    `${teamDomain}/cdn-cgi/access/certs`
  );

  if (!certsResponse.ok) {
    throw new Error(
      "Nie udało się pobrać kluczy Cloudflare Access."
    );
  }

  const certs = await certsResponse.json();

  const jwk = certs.keys.find(
    key => key.kid === header.kid
  );

  if (!jwk) {
    throw new Error(
      "Nie znaleziono klucza podpisu Cloudflare."
    );
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const signedData =
    new TextEncoder().encode(
      `${parts[0]}.${parts[1]}`
    );

  const signature =
    base64urlToBytes(parts[2]);

  const validSignature =
    await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signature,
      signedData
    );

  if (!validSignature) {
    throw new Error(
      "Nieprawidłowy podpis Cloudflare Access."
    );
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.exp && payload.exp < now) {
    throw new Error(
      "Sesja Cloudflare Access wygasła."
    );
  }

  if (
    payload.iss !== teamDomain
  ) {
    throw new Error(
      "Nieprawidłowy issuer Cloudflare Access."
    );
  }

  const expectedAud = String(
    env.POLICY_AUD || ""
  );

  const aud = Array.isArray(payload.aud)
    ? payload.aud
    : [payload.aud];

  if (!aud.includes(expectedAud)) {
    throw new Error(
      "Token nie jest przeznaczony dla tej aplikacji."
    );
  }

  return payload;
}

function isAdmin(payload, env) {
  const loggedInEmail = String(
    payload.email || ""
  )
    .trim()
    .toLowerCase();

  const adminEmail = String(
    env.ADMIN_EMAIL || ""
  )
    .trim()
    .toLowerCase();

  return (
    loggedInEmail &&
    adminEmail &&
    loggedInEmail === adminEmail
  );
}

async function appendNews(env, token, values) {
  const range = "'WWW_AKTUALNOSCI'!A:F";

  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}/values/` +
    `${encodeURIComponent(range)}:append` +
    `?valueInputOption=USER_ENTERED` +
    `&insertDataOption=INSERT_ROWS`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      values: [values]
    })
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      "Google Sheets append failed: " +
        JSON.stringify(result)
    );
  }

  return result;
}

export async function onRequestPost(context) {
  try {
    const accessUser =
      await verifyCloudflareAccess(
        context.request,
        context.env
      );

    if (!isAdmin(accessUser, context.env)) {
      return Response.json(
        {
          ok: false,
          error:
            "Brak uprawnień administratora."
        },
        {
          status: 403
        }
      );
    }

    const body =
      await context.request.json();

    const title = String(
      body.title || ""
    ).trim();

    const category = String(
      body.category || "Aktualność"
    ).trim();

    const text = String(
      body.text || ""
    ).trim();

    const published =
      body.published === false
        ? "NIE"
        : "TAK";

    if (!title || !text) {
      return Response.json(
        {
          ok: false,
          error:
            "Tytuł i treść są wymagane."
        },
        {
          status: 400
        }
      );
    }

    if (title.length > 180) {
      return Response.json(
        {
          ok: false,
          error:
            "Tytuł jest zbyt długi."
        },
        {
          status: 400
        }
      );
    }

    if (text.length > 10000) {
      return Response.json(
        {
          ok: false,
          error:
            "Treść jest zbyt długa."
        },
        {
          status: 400
        }
      );
    }

    const id =
      crypto.randomUUID();

    const now = new Date();

    const date =
      String(now.getDate()).padStart(2, "0") +
      "." +
      String(now.getMonth() + 1).padStart(2, "0") +
      "." +
      now.getFullYear();

    const googleToken =
      await getGoogleAccessToken(
        context.env
      );

    await appendNews(
      context.env,
      googleToken,
      [
        id,
        date,
        category,
        title,
        text,
        published
      ]
    );

    return Response.json({
      ok: true,
      id,
      date
    });

  } catch (error) {
    return Response.json(
      {
        ok: false,
        error: error.message
      },
      {
        status: 403
      }
    );
  }
}
