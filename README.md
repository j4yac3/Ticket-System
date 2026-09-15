# Ticket System

A lightweight, responsive, full-stack IT Support and Ticketing System built with React, Vite, Node.js (Express), and SQLite.

## Features

- **Ticket Management**: Create, update, and manage support tickets with statuses (Open, In Progress, Waiting, Solved) and categories (Hardware, Software, Loan).
- **Dashboard & Analytics**: View key metrics, such as open tickets, resolved tickets, and month-over-month comparisons.
- **User Authentication**: Secure session-based authentication with support for OAuth and self-registration.
- **Role-Based Access Control**: Differentiates between regular users and administrators (IT-Support). Admins have extended permissions.
- **Email Notifications**: Built-in SMTP support via Nodemailer to notify users about ticket updates.
- **Security**: Features secure password hashing (scrypt), rate limiting (express-rate-limit), and secure HTTP headers (Helmet).
- **Zero-Config Database**: Utilizes Node's native SQLite (`node:sqlite`) implementation, storing data locally without requiring a separate database server setup.

## Prerequisites

- Node.js (Version 22.x or later is recommended to fully support `node:sqlite`).
- npm (or another package manager of your choice).

## Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/j4yac3/Ticket-System.git
   cd Ticket-System
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   Copy `.env.example` to `.env` and configure your local environment settings:
   ```bash
   cp .env.example .env
   ```
   *Make sure to configure the SMTP settings if you wish to use email notifications, and set the appropriate `PORT` or `APP_URL`.*

4. **Development**
   Start the frontend development server and backend API server simultaneously or separately.
   - Frontend (Vite): `npm run dev`
   - Backend (Express): `npm run server`

5. **Production Build**
   Build the React frontend and run the Node server, which will serve the static built files from the `dist` directory.
   ```bash
   npm run build
   npm start
   ```

## Tech Stack

- **Frontend**: React 19, Vite
- **Backend**: Node.js, Express 5, Zod (for validation)
- **Database**: SQLite (using `node:sqlite`)
- **Security & Mail**: Helmet, Rate-Limiting, Nodemailer, node:crypto

## License

This project is intended for personal or internal organizational use. Check standard license files if applicable.
