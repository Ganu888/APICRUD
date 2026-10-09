# JSON API Platform — Node.js + Express + MongoDB

A small JSON API management website:
- Developer/admin creates user accounts (no public registration).
- Users log in with username/password.
- Each user can create, read, update and delete their own JSON API documents.
- Published APIs are available as public GET-only raw JSON URLs.
- Private CRUD routes require login and verify API ownership.
- Passwords are hashed with bcrypt; sessions are stored in MongoDB.
- Basic security headers and login rate limiting are enabled.

## Requirements
- Node.js 18+
- MongoDB local or MongoDB Atlas

## Setup
1. Extract this ZIP and open a terminal in the project folder.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Copy `.env.example` to `.env` and edit the values. Set a long random `SESSION_SECRET` and change `ADMIN_PASSWORD`.
4. Ensure MongoDB is running, then start:
   ```bash
   npm start
   ```
   Development mode: `npm run dev`
5. Open http://localhost:3000

Initial admin credentials are taken from `.env` (`ADMIN_USERNAME`, `ADMIN_PASSWORD`). The admin account is created only if that username does not already exist. Set a strong password before using outside local development.

## Usage
1. Log in as the admin.
2. Open Manage Users and create user accounts.
3. Log in as a created user.
4. Create an API, provide a name, slug, JSON object/array, and choose whether to publish.
5. A published endpoint will look like `http://localhost:3000/public-api/device-keys`.
6. Anyone can GET a published endpoint; there are no public write routes. Only the owner can edit/delete through the authenticated website.

## Production notes
- Set `NODE_ENV=production`, use HTTPS and a strong `SESSION_SECRET`.
- Set `PUBLIC_BASE_URL` to your real HTTPS domain.
- Use MongoDB Atlas or a secured MongoDB instance, backups and monitoring.
- Only publish non-sensitive JSON. Anyone who knows a published URL can read it.
- The public GET route has basic rate limiting. Consider stricter limits and request logging in production.
# APICRUD
