# Inspect a token visually

The **PQ-JWT Inspector** opens a rich panel that breaks any PostQuantum.Jwt token into its segments — colored by role — and decodes the unencrypted protected header.

- **Selection:** highlight a token and run *PostQuantum.Jwt: Inspect Token (Visual)*.
- **CodeLens:** a **🔍 Inspect PQ-JWT** action appears above tokens in `.cs`, `.json`, and `.http` files.
- **Paste:** run the command with nothing selected and paste a token.

It performs **no cryptography**. It reads structure and the header only — encrypted payloads stay encrypted.
