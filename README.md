# Atlas Panel

Modern JWT Authentication Panel with Dark Theme

## Features

- 🔐 JWT Authentication System
- 👥 User Management (Admin Panel)
- 🔍 Multiple Query Types (TC, Address, Name, etc.)
- 📊 Real-time Statistics
- 🎨 Dark Theme with Animations
- 📱 Responsive Design
- 📋 Export to Excel/TXT/JSON

## Tech Stack

- **Backend:** Node.js, Express.js, JWT
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
- **Icons:** Font Awesome 6.4.0
- **Animations:** AOS (Animate On Scroll)

## Local Development

```bash
npm install
npm start
```

Visit `http://localhost:5000`

## Default Login

- **Admin:** `admin` / `atlas2024`
- **User:** `user1` / `user123`

## Deploy

This project is configured for Vercel deployment with `vercel.json`.

## Environment Variables

- `JWT_SECRET`: JWT signing secret (default: atlas-panel-secret-key-2024)
- `PORT`: Server port (default: 5000)