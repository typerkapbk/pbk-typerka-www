function base64url(input) {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64urlToBytes(input) {
  input = input.replace(/-/g, "+").replace(/_/g, "/");
  while (input.length % 4) input += "=";

  const binary = atob(input);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function decodeJwtPart(part) {
  return JSON.parse(
    new TextDecoder().decode(base64urlToBytes(part))
  );
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

function normalizeTeamDomain(value) {
  let domain = String(value || "").trim();

  if (!domain) return "";

  if (!/^https?:\/\//i.test(domain)) {
    domain = "https://" + domain;
  }

  return domain.replace(/\/+$/, "");
}

async function verifyCloudflareAccess(request, env) {
  const teamDomain = normalizeTeamDomain(env.TEAM_DOMAIN);
  const expectedAud = String(env.POLICY_AUD || "").trim();

  if (!teamDomain) {
    throw new Error("Brak TEAM_DOMAIN.");
  }

  if (!expectedAud) {
    throw new Error("Brak POLICY_AUD.");
  }

  const token = request.headers.get(
    "Cf-Access-Jwt-Assertion"
  );

  if (!token) {
    throw new Error(
      "Brak tokenu Cloudflare Access."
    );
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error(
      "Nieprawidłowy token Cloudflare Access."
    );
  }

  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);

  const certsResponse = await fetch(
    `${teamDomain}/cdn-cgi/access/certs`
  );

  if (!certsResponse.ok) {
    throw new Error(
      "Nie udało się pobrać kluczy Cloudflare Access."
    );
  }

  const certs = await certsResponse.json();

  const jwk = Array.isArray(certs.keys)
    ? certs.keys.find(
        key => key.kid === header.kid
      )
    : null;

  if (!jwk) {
    throw new Error(
      "Nie znaleziono klucza podpisu Cloudflare Access."
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

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    base64urlToBytes(parts[2]),
    new TextEncoder().encode(
      `${parts[0]}.${parts[1]}`
    )
  );

  if (!valid) {
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

  if (payload.nbf && payload.nbf > now) {
    throw new Error(
      "Token Cloudflare nie jest jeszcze ważny."
    );
  }

  const issuer = String(payload.iss || "")
    .replace(/\/+$/, "");

  if (issuer !== teamDomain) {
    throw new Error(
      "Nieprawidłowy TEAM_DOMAIN."
    );
  }

  const audiences = Array.isArray(payload.aud)
    ? payload.aud
    : [payload.aud];

  if (!audiences.includes(expectedAud)) {
    throw new Error(
      "Nieprawidłowy POLICY_AUD."
    );
  }

  return payload;
}

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const payload = {
    iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope:
      "https://www.googleapis.com/auth/spreadsheets.readonly",
    aud:
      "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  };

  const encodedHeader =
    base64url(JSON.stringify(header));

  const encodedPayload =
    base64url(JSON.stringify(payload));

  const unsignedToken =
    `${encodedHeader}.${encodedPayload}`;

  const privateKey =
    String(env.GOOGLE_PRIVATE_KEY || "")
      .replace(/\\n/g, "\n");

  if (
    !env.GOOGLE_SERVICE_ACCOUNT_EMAIL ||
    !privateKey
  ) {
    throw new Error(
      "Brak konfiguracji Google Service Account."
    );
  }

  const cryptoKey =
    await crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(privateKey),
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      cryptoKey,
      new TextEncoder().encode(
        unsignedToken
      )
    );

  const signatureString =
    String.fromCharCode(
      ...new Uint8Array(signature)
    );

  const jwt =
    `${unsignedToken}.` +
    base64url(signatureString);

  const response =
    await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          grant_type:
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
          assertion: jwt
        })
      }
    );

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      "Google authentication failed."
    );
  }

  return result.access_token;
}

async function getUsers(env, token) {
  const range =
    "'WWW_UZYTKOWNICY'!A:C";

  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}/values/` +
    `${encodeURIComponent(range)}` +
    `?valueRenderOption=FORMATTED_VALUE`;

  const response =
    await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

  if (!response.ok) {
    const details =
      await response.text();

    throw new Error(
      `Nie udało się odczytać WWW_UZYTKOWNICY ` +
      `(${response.status}). ${details}`
    );
  }

  const result =
    await response.json();

  return Array.isArray(result.values)
    ? result.values
    : [];
}

function activeValue(value) {
  const v =
    String(value ?? "TAK")
      .trim()
      .toUpperCase();

  return ![
    "NIE",
    "NO",
    "FALSE",
    "0"
  ].includes(v);
}

export async function onRequestGet(context) {
  try {
    const access =
      await verifyCloudflareAccess(
        context.request,
        context.env
      );

    const email =
      String(access.email || "")
        .trim()
        .toLowerCase();

    if (!email) {
      throw new Error(
        "Cloudflare Access nie zwrócił adresu e-mail."
      );
    }

    const adminEmail =
      String(
        context.env.ADMIN_EMAIL || ""
      )
        .trim()
        .toLowerCase();

    const isAdmin =
      !!adminEmail &&
      email === adminEmail;

    const googleToken =
      await getGoogleAccessToken(
        context.env
      );

    const rows =
      await getUsers(
        context.env,
        googleToken
      );

    let name = "";
    let found = false;

    for (
      let i = 1;
      i < rows.length;
      i++
    ) {
      const row =
        Array.isArray(rows[i])
          ? rows[i]
          : [];

      const rowEmail =
        String(row[0] || "")
          .trim()
          .toLowerCase();

      const rowName =
        String(row[1] || "")
          .trim();

      const isActive =
        activeValue(row[2]);

      if (
        rowEmail === email &&
        rowName &&
        isActive
      ) {
        name = rowName;
        found = true;
        break;
      }
    }

    if (!name) {
      const localPart =
        email.split("@")[0] ||
        "Zawodnik";

      name =
        localPart.charAt(0).toUpperCase() +
        localPart.slice(1);
    }

    return Response.json(
      {
        ok: true,
        name,
        isAdmin,
        found
      },
      {
        headers: {
          "Cache-Control":
            "no-store, no-cache, must-revalidate"
        }
      }
    );
  } catch (error) {
    return Response.json(
      {
        ok: false,
        error:
          error instanceof Error
            ? error.message
            : String(error)
      },
      {
        status: 403,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }
}
