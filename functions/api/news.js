function base64url(input) {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64urlToBytes(input) {
  input = input
    .replace(/-/g, "+")
    .replace(/_/g, "/");

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
  return JSON.parse(
    new TextDecoder().decode(bytes)
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

  if (!domain) {
    return "";
  }

  if (
    !domain.startsWith("https://") &&
    !domain.startsWith("http://")
  ) {
    domain = "https://" + domain;
  }

  return domain.replace(/\/+$/, "");
}

async function verifyCloudflareAccess(
  request,
  env
) {
  const teamDomain =
    normalizeTeamDomain(env.TEAM_DOMAIN);

  const expectedAud =
    String(env.POLICY_AUD || "").trim();

  if (!teamDomain) {
    throw new Error(
      "Brak zmiennej TEAM_DOMAIN w Cloudflare."
    );
  }

  if (!expectedAud) {
    throw new Error(
      "Brak zmiennej POLICY_AUD w Cloudflare."
    );
  }

  const token =
    request.headers.get(
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

  const header =
    decodeJwtPart(parts[0]);

  const payload =
    decodeJwtPart(parts[1]);

  if (
    header.alg &&
    header.alg !== "RS256"
  ) {
    throw new Error(
      "Nieobsługiwany algorytm JWT."
    );
  }

  const certsUrl =
    `${teamDomain}/cdn-cgi/access/certs`;

  const certsResponse =
    await fetch(certsUrl);

  if (!certsResponse.ok) {
    throw new Error(
      "Nie udało się pobrać kluczy Cloudflare Access."
    );
  }

  const certs =
    await certsResponse.json();

  if (!Array.isArray(certs.keys)) {
    throw new Error(
      "Cloudflare nie zwrócił prawidłowych kluczy."
    );
  }

  const jwk =
    certs.keys.find(
      key => key.kid === header.kid
    );

  if (!jwk) {
    throw new Error(
      "Nie znaleziono klucza podpisu JWT."
    );
  }

  const publicKey =
    await crypto.subtle.importKey(
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

  const valid =
    await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signature,
      signedData
    );

  if (!valid) {
    throw new Error(
      "Nieprawidłowy podpis Cloudflare Access."
    );
  }

  const now =
    Math.floor(Date.now() / 1000);

  if (
    payload.exp &&
    payload.exp < now
  ) {
    throw new Error(
      "Sesja Cloudflare Access wygasła."
    );
  }

  if (
    payload.nbf &&
    payload.nbf > now
  ) {
    throw new Error(
      "Token Cloudflare nie jest jeszcze ważny."
    );
  }

  const issuer =
    String(payload.iss || "")
      .replace(/\/+$/, "");

  if (issuer !== teamDomain) {
    throw new Error(
      "Nieprawidłowy TEAM_DOMAIN."
    );
  }

  const audiences =
    Array.isArray(payload.aud)
      ? payload.aud
      : [payload.aud];

  if (
    !audiences.includes(expectedAud)
  ) {
    throw new Error(
      "Nieprawidłowy POLICY_AUD."
    );
  }

  return payload;
}

function checkAdmin(payload, env) {
  const loggedInEmail =
    String(payload.email || "")
      .trim()
      .toLowerCase();

  const adminEmail =
    String(env.ADMIN_EMAIL || "")
      .trim()
      .toLowerCase();

  if (!adminEmail) {
    throw new Error(
      "Brak zmiennej ADMIN_EMAIL w Cloudflare."
    );
  }

  return {
    loggedInEmail,
    isAdmin:
      loggedInEmail === adminEmail
  };
}

async function getGoogleAccessToken(env) {
  if (!env.GOOGLE_SERVICE_ACCOUNT_EMAIL) {
    throw new Error(
      "Brak GOOGLE_SERVICE_ACCOUNT_EMAIL."
    );
  }

  if (!env.GOOGLE_PRIVATE_KEY) {
    throw new Error(
      "Brak GOOGLE_PRIVATE_KEY."
    );
  }

  const now =
    Math.floor(Date.now() / 1000);

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const payload = {
    iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope:
      "https://www.googleapis.com/auth/spreadsheets",
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
    String(env.GOOGLE_PRIVATE_KEY)
      .replace(/\\n/g, "\n");

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
      "Google authentication failed: " +
      JSON.stringify(result)
    );
  }

  return result.access_token;
}

async function appendNews(
  env,
  token,
  values
) {
  if (!env.GOOGLE_SHEET_ID) {
    throw new Error(
      "Brak GOOGLE_SHEET_ID."
    );
  }

  const range =
    "'WWW_AKTUALNOSCI'!A:F";

  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}/values/` +
    `${encodeURIComponent(range)}:append` +
    `?valueInputOption=USER_ENTERED` +
    `&insertDataOption=INSERT_ROWS`;

  const response =
    await fetch(url, {
      method: "POST",
      headers: {
        Authorization:
          `Bearer ${token}`,
        "Content-Type":
          "application/json"
      },
      body: JSON.stringify({
        values: [values]
      })
    });

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      "Google Sheets append failed: " +
      JSON.stringify(result)
    );
  }

  return result;
}

function getPolishDate() {
  const parts =
    new Intl.DateTimeFormat(
      "pl-PL",
      {
        timeZone: "Europe/Warsaw",
        day: "2-digit",
        month: "2-digit",
        year: "numeric"
      }
    ).formatToParts(new Date());

  const get =
    type =>
      parts.find(
        part => part.type === type
      )?.value || "";

  return (
    `${get("day")}.` +
    `${get("month")}.` +
    `${get("year")}`
  );
}

export async function onRequestGet(context) {
  return Response.json({
    ok: true,
    endpoint: "PBK Typerka news API",
    variables: {
      TEAM_DOMAIN:
        !!context.env.TEAM_DOMAIN,
      POLICY_AUD:
        !!context.env.POLICY_AUD,
      ADMIN_EMAIL:
        !!context.env.ADMIN_EMAIL,
      GOOGLE_SHEET_ID:
        !!context.env.GOOGLE_SHEET_ID,
      GOOGLE_SERVICE_ACCOUNT_EMAIL:
        !!context.env
          .GOOGLE_SERVICE_ACCOUNT_EMAIL,
      GOOGLE_PRIVATE_KEY:
        !!context.env.GOOGLE_PRIVATE_KEY
    }
  });
}

export async function onRequestPost(context) {
  try {
    const accessPayload =
      await verifyCloudflareAccess(
        context.request,
        context.env
      );

    const admin =
      checkAdmin(
        accessPayload,
        context.env
      );

    if (!admin.isAdmin) {
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

    let body;

    try {
      body =
        await context.request.json();
    } catch {
      return Response.json(
        {
          ok: false,
          error:
            "Nieprawidłowe dane JSON."
        },
        {
          status: 400
        }
      );
    }

    const title =
      String(body.title || "").trim();

    const category =
      String(
        body.category || "Aktualność"
      ).trim();

    const text =
      String(body.text || "").trim();

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

    const date =
      getPolishDate();

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
        error:
          error instanceof Error
            ? error.message
            : String(error)
      },
      {
        status: 403
      }
    );
  }
}
