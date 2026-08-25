function base64url(input) {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
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

function getAuthenticatedEmail(request) {
  return (
    request.headers.get(
      "Cf-Access-Authenticated-User-Email"
    ) || ""
  )
    .trim()
    .toLowerCase();
}

function isAdmin(request, env) {
  const loggedInEmail = getAuthenticatedEmail(request);
  const adminEmail = String(env.ADMIN_EMAIL || "")
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
    if (!isAdmin(context.request, context.env)) {
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

    const body = await context.request.json();

    const title = String(body.title || "").trim();
    const category = String(
      body.category || "Aktualność"
    ).trim();
    const text = String(body.text || "").trim();
    const published =
      body.published === false ? "NIE" : "TAK";

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

    const token =
      await getGoogleAccessToken(context.env);

    await appendNews(
      context.env,
      token,
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
        status: 500
      }
    );
  }
}
