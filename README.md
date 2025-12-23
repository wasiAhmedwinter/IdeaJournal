🧠 IdeaJournal

A secure, encrypted idea & journal management web application built with Python.
IdeaJournal lets users safely write, store, manage, and export their ideas — with strong focus on privacy and security.

🚀 Features

🔐 Secure Authentication

Password hashing (no plain-text storage)

Session-based login system

🧠 Encrypted Idea Storage

Each idea is encrypted before saving

Stored as .enc files for maximum privacy

👤 User Isolation

Every user has a separate idea directory

No cross-user data access

📄 PDF Export

Convert encrypted ideas into downloadable PDFs

🛠 Admin Panel

Admin login

View users and stored ideas

Manage system data

🗑 Account Deletion

Deletes user account and associated ideas securely

🏗 Tech Stack

Backend: Python + Flask

Frontend: HTML, CSS

PDF Generation: ReportLab

Security: Password hashing & file-level encryption

Hosting (optional): Render

📂 Project Structure
IdeaJournal/
│
├── app.py
├── requirements.txt
├── README.md
│
├── ideas/
│   ├── user_1/
│   │   └── idea_xxx/
│   │       └── idea.enc
│
├── templates/
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── admin.html
│
├── static/
│   └── styles.css

⚙️ Installation & Setup
1️⃣ Clone the Repository
git clone https://github.com/wasiAhmedwinter/IdeaJournal.git
cd IdeaJournal

2️⃣ Install Dependencies
pip install -r requirements.txt

3️⃣ Run the App
python app.py


Open browser and visit:

http://127.0.0.1:5000

🔐 Security Notes

Passwords are hashed, never stored directly

Ideas are encrypted at rest

Admin and user routes are separated

Session data is cleared on logout and account deletion

⚠️ For production:

Use HTTPS

Add environment variables for secrets

Consider database migration (SQLite/PostgreSQL)

📈 Future Improvements

✅ Database support (SQLite / PostgreSQL)

✅ Better role-based access control

✅ Rate limiting & input validation

✅ Cloud storage integration

✅ Subscription & payment system

✅ API support for mobile apps

🎯 Who Is This For?

Students learning secure backend development

Developers building privacy-focused apps

Anyone who wants a personal encrypted journal

👨‍💻 Author

Wasi Ahmed Choudhary
Diploma in Computer Science (India)
Passionate about backend systems, security, and real-world projects

📜 License

This project is open-source and available for learning and improvement.
(You may add an MIT License later if you want.)
