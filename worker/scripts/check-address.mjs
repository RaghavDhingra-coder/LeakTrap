// Check a FALLBACK_ADDRESS value without uploading it. Same rules and verdicts
// as `node scripts/set-secret.mjs FALLBACK_ADDRESS --check-only`.
//   node scripts/check-address.mjs            (hidden prompt)
import { run } from "./secret-input.mjs";

process.exitCode = await run({
  argv: ["FALLBACK_ADDRESS", "--check-only"], stdin: process.stdin, stdout: process.stdout, stderr: process.stderr,
});
