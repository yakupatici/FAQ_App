# Healthcare IT FAQ System

A web-based FAQ management system for healthcare IT support, built with Flask and Bootstrap. This system allows healthcare staff to quickly find solutions to common technical problems and enables administrators to manage the knowledge base.

## Features

- User Authentication (Login/Register)
- Role-based Access Control (Admin/Regular Users)
- FAQ Management System
- Categorized FAQ Entries
- Search Functionality
- Responsive Design
- Mobile-friendly Interface

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd healthcare-it-faq
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Initialize the database (this will create the admin user):
```bash
python app.py
```

2. Access the application at `http://localhost:5000`

## Default Admin Credentials

- Username: admin
- Password: password

**Important:** Change the admin password after first login for security purposes.

## User Roles

### Admin
- Can add, edit, and delete FAQ entries
- Can manage FAQ categories
- Has access to all regular user features

### Regular Users (Healthcare Staff)
- Can view FAQ entries
- Can search through FAQs
- Can filter FAQs by category

## FAQ Categories

The system includes the following predefined categories:
- PC
- Printer
- QR Code Printer
- Network
- Software
- Other

## Security Notes

1. Change the default admin password immediately after first login
2. The application uses secure password hashing
3. Session-based authentication is implemented
4. Role-based access control is enforced

## Development

The application is built with:
- Flask - Web framework
- SQLAlchemy - Database ORM
- Flask-Login - User session management
- Bootstrap 5 - Frontend framework
- SQLite - Database

## Project Structure

```
healthcare-it-faq/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── templates/         # HTML templates
    ├── base.html      # Base template
    ├── index.html     # Landing page
    ├── login.html     # Login form
    ├── register.html  # Registration form
    ├── dashboard.html # User dashboard
    └── manage_faqs.html # Admin FAQ management
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 