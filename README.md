# Email Validator

This Python script validates email addresses in a mailing list CSV by checking their syntax, domain status, MX records, and whether they belong to known disposable email providers or blacklisted domains. It uses external blocklists for disposable and malicious domains.

## Features

- Validates email syntax using regex
- Checks if the domain has valid DNS A records
- Checks if the domain has MX records
- Detects known disposable email domains
- Detects role-based email addresses
- Checks if the domain is blacklisted using an external malicious blocklist

## Requirements

- Python 3.x
- `requests` module
- `dnspython` module

## Installation

### macOS

1. **Install Homebrew** (if you don't have it already):

    Homebrew is a package manager for macOS that makes it easy to install software.

    ```sh
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

2. **Install Python** (if you don't have it already):

    Homebrew can be used to install Python.

    ```sh
    brew install python
    ```

3. **Install `pip`** (Python package manager) if it isn't installed:

    You can install `pip` using Homebrew as well.

    ```sh
    brew install pip
    ```

4. **Create a virtual environment** (optional but recommended):

    A virtual environment isolates your Python dependencies for this project.

    ```sh
    python3 -m venv email-validator-env
    source email-validator-env/bin/activate
    ```

5. **Install the required Python packages**:

    Install the `requests` and `dnspython` modules using `pip`.

    ```sh
    pip install requests dnspython
    ```

## Usage

1. Clone the repository:

    ```sh
    git clone https://github.com/jameshobden/email-validator.git
    cd email-validator
    ```

2. Place your input CSV file (`input_emails.csv`) in the same directory. The CSV file should have columns `email` and `status`.

3. Run the script:

    ```sh
    python script.py
    ```

4. The script will generate an `blacklisted_emails.csv` file containing the emails that failed validation.

## Script Details

### Functions

- `is_valid_email_syntax(email)`: Validates email syntax using regex.
- `load_blocklist(file_path)`: Loads blocklist from a specified file.
- `is_blacklisted_domain(email, blocklist)`: Checks if the email domain is blacklisted.
- `is_disposable_email(email, disposable_domains)`: Checks if the email domain is from a known disposable email provider.
- `is_role_based_email(email)`: Checks if the email is a role-based email address.
- `has_valid_domain(email)`: Checks if the domain has valid DNS A records with caching and rate limiting.
- `has_mx_record(email)`: Checks if the domain has MX records with caching and rate limiting.
- `download_file(url, output_file)`: Downloads a file from a URL if it doesn't exist.
- `validate_emails(input_csv, output_csv, disposable_file, malicious_file)`: Reads emails from CSV, validates them, and updates the input CSV.

### Blocklists

- Disposable email domains list: [disposable_email_blocklist.conf](https://github.com/disposable-email-domains/disposable-email-domains/blob/master/disposable_email_blocklist.conf)
- Malicious domains blocklist: [ultimate.txt](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/ultimate.txt)

The script automatically downloads these lists if they are not present in the directory.

## Contributing

Feel free!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

## Acknowledgments

- [Homebrew](https://brew.sh/)
- [requests](https://docs.python-requests.org/en/latest/)
- [dnspython](http://www.dnspython.org/)
- [Disposable Email Domains](https://github.com/disposable-email-domains/disposable-email-domains)
- [Hagezi's DNS Blocklists](https://github.com/hagezi/dns-blocklists)

