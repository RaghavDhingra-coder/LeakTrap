// Set one of the Worker's secrets safely. The value is read from a hidden
// prompt (or from a pipe, e.g. a password manager), validated with the
// Worker's own rules, never printed, and uploaded only if it is valid. For
// INGEST_SECRET it must also equal LEAKTRACE_INGEST_SECRET on Render.
//
//   node scripts/set-secret.mjs INGEST_SECRET [--check-only]
//   node scripts/set-secret.mjs FALLBACK_ADDRESS [--check-only]
//   security find-generic-password -s leaktrace-ingest-secret -w | node scripts/set-secret.mjs INGEST_SECRET
import { run } from "./secret-input.mjs";

process.exitCode = await run({
  argv: process.argv.slice(2), stdin: process.stdin, stdout: process.stdout, stderr: process.stderr,
});
