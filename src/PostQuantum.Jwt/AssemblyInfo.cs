// The public surface exposes cryptographic interop types (e.g. byte[] keys) that
// are intentionally not CLS-compliant; advertise that honestly.
[assembly: System.CLSCompliant(false)]

// Tests exercise the internal X-Wing KEM engine directly.
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("PostQuantum.Jwt.Tests")]
