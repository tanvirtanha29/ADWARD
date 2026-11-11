# MHT Earning Website

User site : https://YOUR-NAME.onrender.com/
Admin     : https://YOUR-NAME.onrender.com/admin   (password দিয়ে ঢুকতে হবে)

Admin pages: /admin, /admin/user, /admin/tasks, /admin/watch, /admin/withdrawal, /admin/logout

## Render setup
1. সব ফাইল GitHub repo-র root-এ আপলোড করুন (কোনো folder লাগবে না)
2. Render -> New -> Web Service -> repo select
3. Runtime: Node | Build Command: (ফাঁকা বা `echo ok`) | Start Command: `node server.js`
4. Environment Variables: ADMIN_PASSWORD = আপনার পাসওয়ার্ড, SESSION_SECRET = যেকোনো লম্বা random লেখা
