# atscheck.py — ATS checker para IPA

Verifica `NSAppTransportSecurity` em **qualquer** .ipa, listando exceções por domínio:
- `NSExceptionAllowsInsecureHTTPLoads` (e `NSTemporary*`)
- `NSIncludesSubdomains`
- `NSRequiresCertificateTransparency`
- TLS mínimo / Forward Secrecy
- **Effective HTTP permitted** (True se o app aceitar HTTP por exceção ou global)

## Uso
```bash
python3 atscheck.py app.ipa
python3 atscheck.py app.ipa --json
python3 atscheck.py app.ipa --no-color
