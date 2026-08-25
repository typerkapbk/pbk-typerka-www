export async function onRequestGet(context) {
  return Response.json({
    TEAM_DOMAIN: !!context.env.TEAM_DOMAIN,
    POLICY_AUD: !!context.env.POLICY_AUD,
    ADMIN_EMAIL: !!context.env.ADMIN_EMAIL,
    GOOGLE_SHEET_ID: !!context.env.GOOGLE_SHEET_ID,
    GOOGLE_SERVICE_ACCOUNT_EMAIL:
      !!context.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    GOOGLE_PRIVATE_KEY:
      !!context.env.GOOGLE_PRIVATE_KEY
  });
}

