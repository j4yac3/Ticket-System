const fs = require('fs');

// ══════════════════════════════════════════════════════
// PART 1: Fix dark blue theme-toggle button in App.css
// ══════════════════════════════════════════════════════
let css = fs.readFileSync('src/App.css', 'utf8');

// Replace the dark-blue/slate enabled state (#22323c) with warm dark charcoal + red accent
css = css.replace(
  '.theme-toggle.enabled { background: #22323c; color: #fff; border-color: #22323c; }',
  '.theme-toggle.enabled { background: #2a1c20; color: #fff; border-color: #6b1515; }'
);
// Also fix the indicator dot in active state (was amber #f2c66d, keep it as a warm accent)
// The dot is fine, keep it

// Add dark-mode override for theme-toggle so the inactive state looks right too
if (!css.includes('.dark-mode .theme-toggle {')) {
  css += `
/* [TEMPLATE CUSTOMIZATION] Dark mode appearance toggle button */
.dark-mode .theme-toggle { background: #2a1c1c; color: #e8d0d0; border-color: #4a3535; }
.dark-mode .theme-toggle span { background: #6b1515; }
.dark-mode .theme-toggle.enabled { background: #6b1515; border-color: #8a2020; }
.dark-mode .theme-toggle.enabled span { background: #f2c66d; }
`;
}

fs.writeFileSync('src/App.css', css, 'utf8');
console.log('✓ Part 1: Theme toggle button fixed.');


// ══════════════════════════════════════════════════════
// PART 2: Code Sanitization — server.js
// ══════════════════════════════════════════════════════
let server = fs.readFileSync('server.js', 'utf8');

// Remove real email and password from admin bootstrap
server = server.replace(
  `const adminEmail = 'niroxbbx2020@gmail.com'`,
  `// [TEMPLATE CUSTOMIZATION] Change this to your admin email address\nconst adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com'`
);
server = server.replace(
  `const adminBootstrapPassword = 'Jayace!2026#ServiceDesk'`,
  `// [TEMPLATE CUSTOMIZATION] Change this or set ADMIN_PASSWORD env var. User is forced to change on first login.\nconst adminBootstrapPassword = process.env.ADMIN_PASSWORD || 'ChangeMe!2024#Admin'`
);

// Replace private company name in TOTP URI
server = server.replace(
  /Jayace%20IT%20Service/g,
  'Ticket%20System'
);
server = server.replace(
  /issuer=Jayace%20IT%20Service/g,
  'issuer=Ticket%20System'
);

fs.writeFileSync('server.js', server, 'utf8');
console.log('✓ Part 2: server.js sanitized.');


// ══════════════════════════════════════════════════════
// PART 2b: Sanitize App.jsx placeholder email
// ══════════════════════════════════════════════════════
let jsx = fs.readFileSync('src/App.jsx', 'utf8');

jsx = jsx.replace(
  'placeholder="z.B. opa@zuhause.de"',
  'placeholder="z.B. user@example.com"'
);

// Add [TEMPLATE CUSTOMIZATION] comment to brand logo in App.jsx
jsx = jsx.replace(
  `<span className="brand-logo"><span className="brand-ticket">Ticket</span><span className="brand-system">System</span></span>`,
  `{/* [TEMPLATE CUSTOMIZATION] Change "Ticket" and "System" to your own app name */}
            <span className="brand-logo"><span className="brand-ticket">Ticket</span><span className="brand-system">System</span></span>`
);

fs.writeFileSync('src/App.jsx', jsx, 'utf8');
console.log('✓ Part 2b: App.jsx sanitized and branded.');


// ══════════════════════════════════════════════════════
// PART 3: Add customization comments to App.css
// ══════════════════════════════════════════════════════
// Already have the CSS file, add a big comment block at the top of the :root section
css = fs.readFileSync('src/App.css', 'utf8');

const rootComment = `/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║           TICKET SYSTEM — CSS CUSTOMIZATION GUIDE           ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║                                                              ║
 * ║  [TEMPLATE CUSTOMIZATION]                                    ║
 * ║  To change the color theme, update the CSS variables below.  ║
 * ║                                                              ║
 * ║  --teal:       Primary brand color (buttons, active states)  ║
 * ║  --teal-dark:  Darker shade for hovers and sidebar           ║
 * ║  --soft-teal:  Light background tint for cards               ║
 * ║  --coral:      Accent color (badges, priorities)             ║
 * ║                                                              ║
 * ║  Example: Replace the red theme with a blue theme:           ║
 * ║    --teal: #1a56db;                                          ║
 * ║    --teal-dark: #1e429f;                                     ║
 * ║    --soft-teal: #e1effe;                                     ║
 * ║                                                              ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

`;

if (!css.startsWith('/*')) {
  css = rootComment + css;
}

fs.writeFileSync('src/App.css', css, 'utf8');
console.log('✓ Part 3: Customization comments added to App.css.');

console.log('\nAll parts done. Now build and push.');
