# AWAKE

**Android Wiki of Attacks, Knowledge & Exploits**

A comprehensive, open-source documentation project dedicated to Android security research, vulnerability analysis, and exploitation techniques.

---

## Overview

AWAKE serves as a centralized knowledge repository for Android security researchers, penetration testers, malware analysts, and developers seeking to understand the Android security landscape. This wiki documents attack vectors, permission exploits, vulnerability research, and defensive mechanisms within the Android ecosystem.

The project aims to bridge the gap between fragmented security research and provide a structured, accessible reference for both offensive and defensive security practitioners.

## Content Areas

### Permission System Exploits
In-depth analysis of Android permission model vulnerabilities, including privilege escalation techniques, permission bypass methods, and exploitation of confused deputy problems.

### Attack Vectors
Documentation of various attack methods targeting Android applications and the operating system, covering local and remote exploitation, inter-process communication vulnerabilities, and supply chain attacks.

### Malware Analysis
Comprehensive breakdowns of Android malware families, their behaviors, persistence mechanisms, command and control protocols, and indicators of compromise.

### Platform Security Mechanisms
Examination of Android's security architecture including SELinux policies, application sandboxing, verified boot, and their known limitations or bypass techniques.

### Vulnerability Research
Detailed technical writeups of discovered vulnerabilities, proof-of-concept exploits, and security advisories affecting Android devices and applications.

## Documentation

The full documentation is built with MkDocs Material and is available at:

**https://zahidaz.github.io/awake/**

## Local Development

To build and preview the documentation locally:

```bash
uv pip install -e .
mkdocs serve
```

The documentation will be available at `http://127.0.0.1:8000`

## Contributing

Contributions are welcome in the form of:

- New vulnerability documentation
- Malware analysis reports
- Attack technique descriptions
- Corrections and improvements to existing content
- Tool and script contributions

Please ensure all contributions:

1. Are technically accurate and verifiable
2. Include proper references and citations
3. Follow the existing documentation structure
4. Do not include active exploit code for unpatched vulnerabilities

## Responsible Disclosure

This project documents publicly disclosed vulnerabilities and research. If you discover new vulnerabilities:

- Follow responsible disclosure practices
- Report to Google Android Security Team
- Only document after official patches are available

## Legal and Ethical Considerations

This documentation is provided strictly for:

- Educational purposes
- Defensive security research
- Authorized security testing
- Academic research

**Users are responsible for ensuring their use of this information complies with all applicable laws and regulations. Unauthorized access to computer systems is illegal.**

## License

This project is open-source and available for educational and research purposes. See individual documents for specific licensing information.

## Disclaimer

The information in this wiki is provided "as is" without warranty of any kind. The maintainers are not responsible for any misuse of the information contained herein. All techniques and exploits should only be used in authorized testing environments with proper permissions.

---

**Project Status:** Active Development

**Last Updated:** 2026-01-29
