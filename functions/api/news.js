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
    throw new Error(
      "Brak zmiennej TEAM_DOMAIN w Cloudflare."
    );
  }

  if (!expectedAud) {
    throw new Error(
      "Brak zmiennej POLICY_AUD w Cloudflare."
    );
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

  if (header.alg && header.alg !== "RS256") {
    throw new Error(
      "Nieobsługiwany algorytm JWT."
    );
  }

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
      "Nie znaleziono klucza podpisu JWT."
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

function requireAdmin(payload, env) {
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

  if (!adminEmail) {
    throw new Error(
      "Brak zmiennej ADMIN_EMAIL w Cloudflare."
    );
  }

  if (
    !loggedInEmail ||
    loggedInEmail !== adminEmail
  ) {
    const error = new Error(
      "Brak uprawnień administratora."
    );

    error.status = 403;
    throw error;
  }
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

  const now = Math.floor(Date.now() / 1000);

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

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      "Google authentication failed: " +
      JSON.stringify(result)
    );
  }

  return result.access_token;
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

  const get = type =>
    parts.find(
      part => part.type === type
    )?.value || "";

  return (
    `${get("day")}.` +
    `${get("month")}.` +
    `${get("year")}`
  );
}

function validateNewsBody(body) {
  const title = String(
    body.title || ""
  ).trim();

  const category =
    String(
      body.category || "Aktualność"
    ).trim() || "Aktualność";

  const text = String(
    body.text || ""
  ).trim();

  const published =
    body.published === false
      ? "NIE"
      : "TAK";

  if (!title || !text) {
    const error = new Error(
      "Tytuł i treść są wymagane."
    );

    error.status = 400;
    throw error;
  }

  if (title.length > 180) {
    const error = new Error(
      "Tytuł jest zbyt długi."
    );

    error.status = 400;
    throw error;
  }

  if (text.length > 10000) {
    const error = new Error(
      "Treść jest zbyt długa."
    );

    error.status = 400;
    throw error;
  }

  return {
    title,
    category,
    text,
    published
  };
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

async function findNewsRow(
  env,
  token,
  id
) {
  const range =
    "'WWW_AKTUALNOSCI'!A:F";

  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}/values/` +
    `${encodeURIComponent(range)}` +
    `?valueRenderOption=FORMATTED_VALUE`;

  const response =
    await fetch(url, {
      headers: {
        Authorization:
          `Bearer ${token}`
      }
    });

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      "Nie udało się odczytać aktualności: " +
      JSON.stringify(result)
    );
  }

  const rows =
    Array.isArray(result.values)
      ? result.values
      : [];

  for (
    let i = 1;
    i < rows.length;
    i++
  ) {
    if (
      String(
        rows[i]?.[0] || ""
      ).trim() === id
    ) {
      return {
        rowNumber: i + 1,
        values: rows[i]
      };
    }
  }

  const error = new Error(
    "Nie znaleziono aktualności o podanym ID."
  );

  error.status = 404;
  throw error;
}

async function updateNews(
  env,
  token,
  rowNumber,
  originalRow,
  news
) {
  const id = String(
    originalRow?.[0] || ""
  ).trim();

  const date =
    String(
      originalRow?.[1] || ""
    ).trim() || getPolishDate();

  const range =
    `'WWW_AKTUALNOSCI'!A${rowNumber}:F${rowNumber}`;

  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}/values/` +
    `${encodeURIComponent(range)}` +
    `?valueInputOption=USER_ENTERED`;

  const response =
    await fetch(url, {
      method: "PUT",
      headers: {
        Authorization:
          `Bearer ${token}`,
        "Content-Type":
          "application/json"
      },
      body: JSON.stringify({
        range,
        majorDimension: "ROWS",
        values: [
          [
            id,
            date,
            news.category,
            news.title,
            news.text,
            news.published
          ]
        ]
      })
    });

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      "Nie udało się zaktualizować aktualności: " +
      JSON.stringify(result)
    );
  }

  return {
    date
  };
}

async function getNewsSheetId(
  env,
  token
) {
  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}` +
    `?fields=sheets(properties(sheetId,title))`;

  const response =
    await fetch(url, {
      headers: {
        Authorization:
          `Bearer ${token}`
      }
    });

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      "Nie udało się pobrać informacji o arkuszu: " +
      JSON.stringify(result)
    );
  }

  const sheet =
    Array.isArray(result.sheets)
      ? result.sheets.find(
          s =>
            s?.properties?.title ===
            "WWW_AKTUALNOSCI"
        )
      : null;

  if (!sheet) {
    throw new Error(
      "Nie znaleziono arkusza WWW_AKTUALNOSCI."
    );
  }

  return sheet.properties.sheetId;
}

async function deleteNewsRow(
  env,
  token,
  rowNumber
) {
  const sheetId =
    await getNewsSheetId(
      env,
      token
    );

  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}:batchUpdate`;

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
        requests: [
          {
            deleteDimension: {
              range: {
                sheetId,
                dimension: "ROWS",
                startIndex:
                  rowNumber - 1,
                endIndex:
                  rowNumber
              }
            }
          }
        ]
      })
    });

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      "Nie udało się usunąć aktualności: " +
      JSON.stringify(result)
    );
  }

  return result;
}

async function authorizeAdmin(
  context
) {
  const accessPayload =
    await verifyCloudflareAccess(
      context.request,
      context.env
    );

  requireAdmin(
    accessPayload,
    context.env
  );

  return accessPayload;
}

function errorResponse(error) {
  const status =
    Number(error?.status) || 500;

  return Response.json(
    {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : String(error)
    },
    {
      status,
      headers: {
        "Cache-Control":
          "no-store"
      }
    }
  );
}

export async function onRequestGet(
  context
) {
  return Response.json(
    {
      ok: true,
      endpoint:
        "PBK Typerka news API",
      methods: [
        "POST",
        "PATCH",
        "DELETE"
      ]
    },
    {
      headers: {
        "Cache-Control":
          "no-store"
      }
    }
  );
}

export async function onRequestPost(
  context
) {
  try {
    await authorizeAdmin(context);

    const body =
      await context.request.json();

    const news =
      validateNewsBody(body);

    const id =
      crypto.randomUUID();

    const date =
      getPolishDate();

    const token =
      await getGoogleAccessToken(
        context.env
      );

    await appendNews(
      context.env,
      token,
      [
        id,
        date,
        news.category,
        news.title,
        news.text,
        news.published
      ]
    );

    return Response.json(
      {
        ok: true,
        id,
        date
      },
      {
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );

  } catch (error) {
    return errorResponse(error);
  }
}

export async function onRequestPatch(
  context
) {
  try {
    await authorizeAdmin(context);

    const body =
      await context.request.json();

    const id =
      String(body.id || "").trim();

    if (!id) {
      const error = new Error(
        "Brak ID aktualności."
      );

      error.status = 400;
      throw error;
    }

    const news =
      validateNewsBody(body);

    const token =
      await getGoogleAccessToken(
        context.env
      );

    const found =
      await findNewsRow(
        context.env,
        token,
        id
      );

    const updated =
      await updateNews(
        context.env,
        token,
        found.rowNumber,
        found.values,
        news
      );

    return Response.json(
      {
        ok: true,
        id,
        date: updated.date
      },
      {
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );

  } catch (error) {
    return errorResponse(error);
  }
}

export async function onRequestDelete(
  context
) {
  try {
    await authorizeAdmin(context);

    let body = {};

    try {
      body =
        await context.request.json();
    } catch {}

    const url =
      new URL(
        context.request.url
      );

    const id =
      String(
        body.id ||
        url.searchParams.get("id") ||
        ""
      ).trim();

    if (!id) {
      const error = new Error(
        "Brak ID aktualności."
      );

      error.status = 400;
      throw error;
    }

    const token =
      await getGoogleAccessToken(
        context.env
      );

    const found =
      await findNewsRow(
        context.env,
        token,
        id
      );

    await deleteNewsRow(
      context.env,
      token,
      found.rowNumber
    );

    return Response.json(
      {
        ok: true,
        id,
        deleted: true
      },
      {
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );

  } catch (error) {
    return errorResponse(error);
  }
}
