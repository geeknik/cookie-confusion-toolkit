# Cookie Confusion Toolkit (CCT)

A security research toolkit for identifying, testing, and validating cookie parsing inconsistencies across browser and server implementations.

## 🔒 Warning: Security Research Tool

This toolkit is designed for **legitimate security research, testing, and educational purposes only**. It helps security professionals identify potential vulnerabilities in web applications related to cookie handling. Misuse of this tool may be illegal and unethical. Always obtain proper authorization before testing any system.

## 🍪 Overview

Cookies remain a fundamental but flawed part of web security. Despite RFCs and browser security improvements, inconsistencies in cookie parsing between clients and servers create security vulnerabilities:

- No version negotiation
- No canonical encoding standard
- Case-insensitive handling inconsistencies
- Silent discards and truncations
- Ambiguous delimiters and parsing rules

The Cookie Confusion Toolkit helps security professionals identify these issues through:

1. **Systematic testing** of cookie handling across browsers and server frameworks
2. **Identification** of parsing inconsistencies that could lead to security bypasses
3. **Documentation** of vulnerabilities for remediation
4. **Responsible disclosure** guidelines and support

## 🧩 Core Modules

- **cookiebomb**: Generate test cases with edge-case cookies (collisions, overlong values, etc.)
- **clientfork**: Emulate browser cookie handling with configurable policies
- **serverdrift**: Test server-side frameworks for parsing inconsistencies
- **bypassgen**: Identify potential security implications of discovered inconsistencies

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Ethical Usage Guidelines](docs/ethical_guidelines.md)
- [Vulnerability Research](docs/vulnerabilities.md)
- [Remediation Strategies](docs/remediation.md)

## 🛡️ Responsible Usage

This toolkit is released under GPLv3 with an additional ethical use clause. By using this software, you agree to:

1. Only test systems you own or have explicit permission to test
2. Follow responsible disclosure practices when vulnerabilities are found
3. Not use this toolkit for unauthorized access or exploitation
4. Share improvements to the wider security community

## 🔬 Research Background

This toolkit is based on extensive research into cookie parsing inconsistencies that affect web security. For technical details on the underlying issues, see [docs/research_background.md](docs/research_background.md).

## 📋 Requirements

- Python 3.9+
- Requests
- Selenium WebDriver
- BeautifulSoup
- Pytest (for running tests)

## 🚀 Quick Start

```bash
# Install from pip
pip install cookie-confusion-toolkit

# Or clone and install
git clone https://github.com/geeknik/cookie-confusion-toolkit.git
cd cookie-confusion-toolkit
pip install -e .

# Run a basic test
python -m cct.test --target example.com
```

## 👥 Contributing

Contributions that improve the toolkit's ability to identify security issues for defensive purposes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 License

GPLv3 with Ethical Use Clause - See [LICENSE](LICENSE) for details.
