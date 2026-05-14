# ChatKit Auth - Role-Based OAuth Worker

A Cloudflare Workers project that implements OAuth 2.0 authentication with Microsoft Entra ID and role-based access control for ChatKit.

## Features

- **Microsoft OAuth 2.0 Integration**: Secure authentication using Microsoft Entra ID
- **Role-Based Access Control**: Different user roles (office, engineer) with specific permissions
- **Session Management**: Secure cookie-based session handling with configurable TTL
- **CORS Support**: Built-in CORS headers for cross-origin requests
- **Serverless Architecture**: Runs on Cloudflare Workers for global edge deployment

## Roles & Permissions

### Office Role
- `view_invoices`
- `view_client_records`
- `approve_status_changes`

### Engineer Role
- `view_service_reports`
- `view_engineer_jobs`
- `update_job_status`

## Prerequisites

- [Node.js](https://nodejs.org/) (v18 or higher)
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/) (installed via npm)
- Cloudflare Workers account
- Microsoft Entra ID application registration

## Installation

```bash
# Install dependencies
npm install

# Generate TypeScript types (if needed)
npx wrangler types
```

## Configuration

### Environment Variables

Create a `.dev.vars` file (never commit this) with the following:

```env
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
AUTH_REDIRECT_URI=https://your-worker.workers.dev/auth/callback
SESSION_SECRET=your_session_secret_key
```

### Wrangler Config

Edit `wrangler.jsonc` to configure your Worker:

```jsonc
{
  "name": "auth-role-worker-poc",
  "main": "src/index.js",
  "workers_dev": true,
  "compatibility_date": "2026-05-12"
}
```

## Development

```bash
# Start local development server
npm run dev
# or
npx wrangler dev
```

The development server will run on `http://localhost:8787` by default.

## Deployment

```bash
# Deploy to Cloudflare Workers
npm run deploy
# or
npx wrangler deploy
```

## API Endpoints

- `GET /` - Health check / landing page
- `POST /auth/login` - Initiate OAuth flow
- `GET /auth/callback` - OAuth callback endpoint
- `POST /auth/logout` - Logout and clear session
- `GET /user` - Get current user info and permissions

## Project Structure

```
src/
├── index.js          # Main Worker handler
wrangler.jsonc       # Wrangler configuration
package.json         # Dependencies and scripts
AGENTS.md            # Additional documentation
```

## Security Considerations

- Session tokens are stored in **httpOnly** cookies
- CSRF protection via state parameter in OAuth flow
- Secrets should never be committed (see `.gitignore`)
- All sensitive data is stored in environment variables

## License

MIT

## Support

For issues or questions, please open an issue on GitHub.