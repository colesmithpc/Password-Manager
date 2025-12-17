# Password Manager

A secure command-line password manager built with Python that stores encrypted passwords locally.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Features

- Secure password storage with encryption
- Master password protection
- Generate strong random passwords
- Add, retrieve, update, and delete password entries
- Store passwords with associated usernames and service names
- Local storage - your passwords never leave your machine

## Installation

Clone the repository:

git clone https://github.com/colesmithpc/tools.git

Navigate to the project directory:

cd tools

Install dependencies:

pip install -r requirements.txt

## Usage

Run the password manager:

python password_manager.py

First time setup: You'll be prompted to create a master password

Add a new password: Follow the prompts to enter service name, username, and password

Retrieve a password: Search by service name to retrieve stored credentials

Generate a strong password: Use the built-in password generator for secure passwords

## Security

- All passwords are encrypted using industry-standard encryption (AES-256)
- Master password is hashed and never stored in plain text
- Passwords are stored locally in an encrypted database
- No cloud storage or third-party services involved

**Important:** Keep your master password safe. If you lose it, your passwords cannot be recovered.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add some amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

Cole Smith - [@colesmithpc](https://github.com/colesmithpc)

Project Link: [https://github.com/colesmithpc/tools](https://github.com/colesmithpc/tools)
