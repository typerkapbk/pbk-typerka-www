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
    scope: "https://www.googleapis.com/auth/spreadsheets.readonly",
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

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt
    })
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      "Google authentication failed: " + JSON.stringify(result)
    );
  }

  return result.access_token;
}

async function getSheetRange(
  env,
  token,
  range,
  valueRenderOption = "UNFORMATTED_VALUE"
) {
  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}/values/${encodeURIComponent(range)}` +
    `?valueRenderOption=${valueRenderOption}`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      `Google Sheets error for ${range}: ` +
      JSON.stringify(result)
    );
  }

  return result.values || [];
}
  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/` +
    `${env.GOOGLE_SHEET_ID}/values/${encodeURIComponent(range)}` +
    `?valueRenderOption=UNFORMATTED_VALUE`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      `Google Sheets error for ${range}: ` +
      JSON.stringify(result)
    );
  }

  return result.values || [];
}

export async function onRequestGet(context) {
  try {
    const token = await getGoogleAccessToken(context.env);

    const [
  generalka,
  tabelaKolejki,
  ms,
  tt,
  aktualnosci
] = await Promise.all([
  getSheetRange(context.env, token, "GENERALKA!A1:I20"),
  getSheetRange(context.env, token, "'TABELA KOLEJKI'!A1:H20"),
  getSheetRange(context.env, token, "'M&S'!A1:AT30"),
  getSheetRange(context.env, token, "TT!A1:BG80"),
  getSheetRange(
  context.env,
  token,
  "'WWW_AKTUALNOSCI'!A1:F200",
  "FORMATTED_VALUE"
)
]);

    return Response.json({
      ok: true,
      timestamp: new Date().toISOString(),
      sheets: {
  GENERALKA: generalka,
  TABELA_KOLEJKI: tabelaKolejki,
  MS: ms,
  TT: tt,
  AKTUALNOSCI: aktualnosci
}
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
