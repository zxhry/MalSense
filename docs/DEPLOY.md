# Deploying MalSense online (Render + TiDB Cloud)

MalSense runs as one Flask web service on Render (free plan) with a MySQL-compatible TiDB Cloud database.
For local use it works with plain MySQL and SMTP email instead (see the main README).

Notes on the online setup:
- Database settings come from environment variables; `DB_SSL=true` turns on TLS (required by TiDB Cloud).
- Behind Render's proxy MalSense uses HTTPS links and secure cookies, and refuses to start without a real `FLASK_SECRET_KEY`.
- Quizzes are stored in the `quiz_cache` table (the server's disk is wiped on restart).
- Email goes through the Gmail API over HTTPS (`MAIL_PROVIDER=gmail_api`), because Render's free plan blocks SMTP ports.
- Retraining and adding samples to the training data are disabled online; they are done locally.
- Reported APKs are kept only until the server restarts (the report record stays in the database).

## 1. Database - TiDB Cloud
1. Create a free cluster at tidbcloud.com (pick region Singapore, close to Render's Singapore region).
2. Open **SQL Editor** and run `database/tidb_setup.sql`.
3. From **Connect**, copy host, port (4000), user and password.
4. Test from your laptop: put those values + `DB_SSL=true` in the project's `.env` (see `.env.example`), then
   `python app.py` and register an account.
5. Make yourself admin: `flask --app app make-admin your@email.com`

## 2. Email - Gmail API (one time)
Follow the steps at the top of `get_gmail_token.py`, then run `python get_gmail_token.py` and keep the
`GMAIL_REFRESH_TOKEN` it prints.

## 3. GitHub
Push the project to your own GitHub repository (it can be private). Check that `.env` is not included.

## 4. Render
1. Render > **New > Blueprint** > pick the repository (it reads `render.yaml`).
2. Fill in the secret values it asks for (same as your `.env`, plus `GMAIL_REFRESH_TOKEN`).
3. Wait for the build, then open the `https://...onrender.com` link.

## 5. Google sign-in
Google Cloud Console > Credentials > your OAuth client > Authorized redirect URIs > add
`https://<your-app>.onrender.com/auth/google/callback`

## 6. Before sharing the link
- Scan your biggest sample APK online and check it finishes (free plan has little memory).
  Intents and API calls are read from the app's code too, so a large APK is the real test.
- The free service sleeps after 15 minutes idle; the first visit then takes about a minute.
