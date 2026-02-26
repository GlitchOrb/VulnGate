-- Example vulnerability seed data for local testing.
-- Equivalent to: vulngate db seed-example

INSERT INTO vulnerabilities (
  id, summary, severity, package_purl, package_key, range_type, events_json, aliases_json, references_json
) VALUES (
  'OSV-2026-0001',
  'Example vulnerable range for demonstration and tests',
  'high',
  'pkg:golang/github.com/example/insecure-lib',
  'golang/github.com/example/insecure-lib',
  'SEMVER',
  '[{"introduced":"0"},{"fixed":"1.2.4"}]',
  '["CVE-2026-0001"]',
  '["https://osv.dev/"]'
);
