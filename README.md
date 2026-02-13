# AWAKE

**Android Wiki of Attacks, Knowledge & Exploits**

Organized Android security research: reversing, exploitation, malware analysis, and the techniques behind them.

---

## About

Android security knowledge is spread across blog posts, conference slides, vendor reports, and dead links. AWAKE structures it in one place with cross-references that individual writeups cannot provide.

This is not a compliance checklist or a defense guide. AWAKE documents how things work and how they break.

## Content

- **Permissions**: Android permissions that can be abused, what they unlock, how malware uses them
- **Attack Techniques**: overlay attacks, intent hijacking, accessibility abuse, WebView exploitation
- **Malware**: families in chronological order, behavioral patterns, naming conventions
- **Packers**: commercial and custom Android packers, identification, protection mechanisms, unpacking
- **Reversing**: static analysis, dynamic analysis, hooking, patching
- **Industry**: mobile security companies and their roles
- **Resources**: curated links to blogs, tools, researchers, conferences

## Documentation

Built with MkDocs Material:

**https://zahidaz.github.io/awake/**

## Local Development

```bash
uv pip install -e .
mkdocs serve
```

## Contributing

Contributions welcome: vulnerability documentation, malware analysis, attack techniques, packer analysis, corrections.

All contributions must be technically accurate and verifiable. No active exploit code for unpatched vulnerabilities.

## License

MIT License. See [LICENSE](LICENSE) for details.
