# Threat Data

**27 UTC dates of telemetry from one public site: 21,296 reported Block decisions and 968 Managed Challenges.**

**Of those Block decisions, 8,106 were attributed to the tracked maintenance rule; 13,190 came from other rules.**

**One investigated scan reached the origin with 72 requests: 71 returned 404, and the public landing page returned 200.**

**Cybersecurity of AMQIC powered by Vallatum.**

Aggregate observations from the public website's scanner-defense operation.

**Observation period:** 22 October 2026, 09:30 UTC–18 November 2026, 00:00 UTC.

**Dataset cutoff:** 18 November 2026, 00:00 UTC.

**Source:** retained Cloudflare security-event aggregates and a bounded diagnostic sample through 12 November at 18:00 UTC; direct Cloudflare Security Events aggregates for the subsequent six intervals.

The retained record starts while the public domain was serving a placeholder and continues through subsequent application releases. It covers the available public-site operation history. The exact initial launch timestamp has not been independently established, so this document makes no claim about activity before the first retained interval.

## Recorded defensive actions

| Action | Provider-reported count |
|---|---:|
| Requests with a Block action | 21,296 |
| Requests with a Managed Challenge action | 968 |
| Managed Challenge events marked non-interactively solved | 11 |
| Managed Challenge events marked bypassed | 24 |
| Log-only events | 2 |

The headline observation is **21,296 reported Block decisions**, including **8,106 attributed to the tracked temporary maintenance rule** and **13,190 from other rules**. The update adds **3,424 Blocks and 181 Managed Challenges** without overlapping the initial archive. These are request-level decisions. The number of distinct attacks, actors, and confirmed malicious visitors remains unknown.

The challenge counts describe recorded actions and outcomes. A challenge being issued does not establish that it was failed. The outcome categories are retained separately and are not added to the block count.

250,251 reported Skip events are excluded from threat totals. The historical archive describes scoped exceptions such as authenticated monitoring, machine API and managed-rule exclusions.

## Daily defensive-action counts

Dates are UTC. The first date is partial. On 12 November, the table combines two disjoint intervals at the 18:00 UTC cutoff. The chart marks the boundary of the direct-query update.

![Daily Block decisions and Managed Challenges, with maintenance-policy denials shown separately](assets/threat-data-daily.png)

| Date | Block | Managed Challenge |
|---|---:|---:|
| 2026-10-22 | 44 | 196 |
| 2026-10-23 | 80 | 390 |
| 2026-10-24 | 1 | 15 |
| 2026-10-25 | 14 | 1 |
| 2026-10-26 | 71 | 2 |
| 2026-10-27 | 811 | 4 |
| 2026-10-28 | 0 | 9 |
| 2026-10-29 | 83 | 6 |
| 2026-10-30 | 709 | 55 |
| 2026-10-31 | 2,311 | 7 |
| 2026-11-01 | 1,870 | 33 |
| 2026-11-02 | 2,466 | 0 |
| 2026-11-03 | 5,630 | 1 |
| 2026-11-04 | 4 | 0 |
| 2026-11-05 | 581 | 5 |
| 2026-11-06 | 442 | 2 |
| 2026-11-07 | 1,585 | 6 |
| 2026-11-08 | 366 | 0 |
| 2026-11-09 | 192 | 6 |
| 2026-11-10 | 100 | 0 |
| 2026-11-11 | 349 | 4 |
| 2026-11-12 | 250 | 51 |
| 2026-11-13 | 484 | 28 |
| 2026-11-14 | 333 | 11 |
| 2026-11-15 | 1,288 | 82 |
| 2026-11-16 | 632 | 44 |
| 2026-11-17 | 600 | 10 |
| **Total** | **21,296** | **968** |

A zero in this table means no action of that type was reported in the retained intervals for that date. It does not establish absence of attempts or traffic.

### Why November 4 dropped to four Blocks

All 5,630 Block decisions on November 3 came from the temporary owner-only maintenance rule. On November 4, the four Block decisions came from the unexpected-port rule. Both dates have a full 24 hours of retained coverage, with no query-limit hit. The change in the chart is a change in the observed policy decisions; it does not establish that attacks fell by the same amount or that a particular fix caused the decline.

The tracked maintenance rule produced 2,450 denials on November 2, 5,630 on November 3 and 26 on November 9. These are explicitly separated in the chart.

## Scanner and sensitive-target probes

This register retains only requests targeting credential files, configuration and diagnostics, database exports, backups, development artifacts, or endpoints associated with unsupported software stacks. Ordinary pages, SEO endpoints, public APIs, published media, fonts, brand assets and routine authentication navigation have been removed. Ambiguous clean navigation paths are omitted.
The historical filtered register (through 12 November at 18:00 UTC) contains **514 distinct path strings and 1,680 stored records**: **1,537 Block records** and **143 Managed Challenge records**. These figures describe the retained diagnostic sample. They do not alter the full security-action totals above.

Paths preserve observed spelling, case, encoding and repeated separators. Opaque identifiers remain replaced. Appearance here identifies the type of probe; it does not identify its operator or establish successful access.

The consolidated register contains **617 distinct public path strings or aliases**: 514 from the historical register and 235 spellings retained from the earlier update, with 132 shared entries shown only once. The current hourly replacement counts are reported below; earlier observed spellings are preserved. Historical sample counts and supplemental provider-reported counts remain in separate columns. Zero means no count in that column’s retained query result, not that the path was never requested. Previously observed spellings remain in the register even if a later sampled query does not return them.

<details>
<summary>Expand all 617 distinct observed probe paths and public aliases</summary>

| Observed probe path or public alias | Historical Block sample | Historical Challenge sample | Update Block count | Update Challenge count |
|---|---:|---:|---:|---:|
| <code>/%252eenv</code> | 0 | 0 | 1 | 0 |
| <code>/%2564b.php</code> | 1 | 0 | 0 | 0 |
| <code>/%2570hpinfo.php</code> | 1 | 0 | 0 | 0 |
| <code>/%2eenv</code> | 1 | 0 | 7 | 0 |
| <code>/%2eenv.local</code> | 0 | 0 | 2 | 0 |
| <code>/%2f%2eaws%2fcredentials</code> | 1 | 0 | 0 | 0 |
| <code>/%2f%2eenv</code> | 1 | 0 | 0 | 0 |
| <code>/.DS_Store</code> | 5 | 0 | 0 | 0 |
| <code>/.ENV</code> | 0 | 0 | 2 | 0 |
| <code>/.Env</code> | 0 | 0 | 1 | 0 |
| <code>/.auth.json</code> | 2 | 0 | 0 | 0 |
| <code>/.aws/.env</code> | 1 | 0 | 0 | 0 |
| <code>/.aws/cli/cache</code> | 2 | 0 | 0 | 0 |
| <code>/.aws/config</code> | 9 | 0 | 7 | 0 |
| <code>/.aws/credentials</code> | 15 | 0 | 11 | 0 |
| <code>/.aws/credentials.bak</code> | 4 | 0 | 2 | 0 |
| <code>/.aws/credentials.json</code> | 0 | 0 | 1 | 0 |
| <code>/.aws/credentials.old</code> | 2 | 0 | 0 | 0 |
| <code>/.aws/credentials.txt</code> | 1 | 0 | 0 | 0 |
| <code>/.aws/credentials~</code> | 2 | 0 | 0 | 0 |
| <code>/.aws/sso/cache.json</code> | 2 | 0 | 0 | 0 |
| <code>/.aws/sso/cache/</code> | 2 | 0 | 0 | 0 |
| <code>/.azure/accessTokens.json</code> | 2 | 0 | 0 | 0 |
| <code>/.azure/azureProfile.json</code> | 2 | 0 | 0 | 0 |
| <code>/.azure/config.json</code> | 2 | 0 | 0 | 0 |
| <code>/.azure/credentials.json</code> | 1 | 0 | 0 | 0 |
| <code>/.azure/msal.json</code> | 1 | 0 | 0 | 0 |
| <code>/.bash_history</code> | 4 | 0 | 0 | 0 |
| <code>/.boto</code> | 2 | 0 | 0 | 0 |
| <code>/.claude/settings.json</code> | 2 | 0 | 4 | 0 |
| <code>/.claude/settings.local.json</code> | 1 | 0 | 0 | 0 |
| <code>/.config.php.swp</code> | 1 | 0 | 0 | 0 |
| <code>/.config/gcloud/application_default_credentials.json</code> | 6 | 0 | 0 | 0 |
| <code>/.cursor/mcp.json</code> | 1 | 0 | 0 | 0 |
| <code>/.docker/.env</code> | 0 | 0 | 1 | 0 |
| <code>/.docker/config.json</code> | 8 | 0 | 10 | 0 |
| <code>/.env</code> | 69 | 5 | 28 | 0 |
| <code>/.env-example</code> | 1 | 0 | 4 | 0 |
| <code>/.env.</code> | 0 | 1 | 0 | 0 |
| <code>/.env.1</code> | 0 | 1 | 2 | 0 |
| <code>/.env.aws</code> | 1 | 0 | 0 | 0 |
| <code>/.env.backup</code> | 6 | 1 | 12 | 0 |
| <code>/.env.bak</code> | 7 | 0 | 15 | 0 |
| <code>/.env.ci</code> | 1 | 0 | 0 | 0 |
| <code>/.env.dev</code> | 28 | 1 | 8 | 0 |
| <code>/.env.dev.local</code> | 1 | 0 | 0 | 0 |
| <code>/.env.development</code> | 3 | 0 | 14 | 0 |
| <code>/.env.development.local</code> | 2 | 0 | 9 | 0 |
| <code>/.env.dist</code> | 0 | 1 | 9 | 0 |
| <code>/.env.docker</code> | 1 | 0 | 12 | 0 |
| <code>/.env.example</code> | 4 | 1 | 13 | 0 |
| <code>/.env.local</code> | 39 | 2 | 22 | 0 |
| <code>/.env.old</code> | 3 | 1 | 16 | 0 |
| <code>/.env.orig</code> | 0 | 1 | 5 | 0 |
| <code>/.env.php</code> | 0 | 1 | 0 | 0 |
| <code>/.env.php.bak</code> | 1 | 1 | 12 | 0 |
| <code>/.env.preview</code> | 1 | 0 | 0 | 0 |
| <code>/.env.prod</code> | 29 | 3 | 6 | 0 |
| <code>/.env.prod.local</code> | 1 | 0 | 2 | 0 |
| <code>/.env.production</code> | 10 | 1 | 19 | 0 |
| <code>/.env.production.local</code> | 4 | 0 | 12 | 0 |
| <code>/.env.qa</code> | 1 | 0 | 0 | 0 |
| <code>/.env.sample</code> | 2 | 0 | 4 | 0 |
| <code>/.env.save</code> | 2 | 0 | 17 | 0 |
| <code>/.env.staging</code> | 5 | 0 | 14 | 0 |
| <code>/.env.test</code> | 5 | 0 | 12 | 0 |
| <code>/.env.testing</code> | 1 | 0 | 6 | 0 |
| <code>/.env.tmp</code> | 1 | 1 | 0 | 0 |
| <code>/.env.txt</code> | 1 | 2 | 0 | 0 |
| <code>/.env.uat</code> | 1 | 0 | 0 | 0 |
| <code>/.env/</code> | 0 | 0 | 2 | 0 |
| <code>/.env1</code> | 0 | 1 | 0 | 0 |
| <code>/.env2</code> | 0 | 1 | 0 | 0 |
| <code>/.env_copy</code> | 1 | 1 | 6 | 0 |
| <code>/.env~</code> | 1 | 0 | 0 | 0 |
| <code>/.git-credentials</code> | 2 | 1 | 0 | 0 |
| <code>/.git/HEAD</code> | 18 | 1 | 27 | 0 |
| <code>/.git/config</code> | 56 | 11 | 24 | 0 |
| <code>/.git/logs/HEAD</code> | 4 | 0 | 0 | 0 |
| <code>/.git/logs/refs/heads/main</code> | 2 | 0 | 0 | 0 |
| <code>/.git/refs/heads/main</code> | 2 | 0 | 0 | 0 |
| <code>/.git/{redacted}</code> | 0 | 0 | 3 | 0 |
| <code>/.gitconfig</code> | 0 | 1 | 0 | 0 |
| <code>/.github/.env</code> | 0 | 0 | 8 | 0 |
| <code>/.github/copilot-instructions.md</code> | 0 | 1 | 0 | 0 |
| <code>/.github/workflows/build.yml</code> | 0 | 1 | 0 | 0 |
| <code>/.github/workflows/ci.yml</code> | 0 | 2 | 0 | 0 |
| <code>/.github/workflows/deploy.yml</code> | 0 | 3 | 0 | 0 |
| <code>/.github/workflows/main.yml</code> | 0 | 1 | 0 | 0 |
| <code>/.gitignore</code> | 0 | 2 | 0 | 0 |
| <code>/.gitlab-ci.yml</code> | 0 | 3 | 0 | 0 |
| <code>/.gitmodules</code> | 0 | 4 | 0 | 0 |
| <code>/.hg/dirstate</code> | 3 | 0 | 0 | 0 |
| <code>/.hg/hgrc</code> | 2 | 0 | 5 | 0 |
| <code>/.hg/requires</code> | 7 | 0 | 0 | 0 |
| <code>/.hg/store/requires</code> | 8 | 0 | 0 | 0 |
| <code>/.htaccess</code> | 2 | 0 | 0 | 0 |
| <code>/.htpasswd</code> | 3 | 0 | 0 | 0 |
| <code>/.idea/workspace.xml</code> | 1 | 0 | 0 | 0 |
| <code>/.kube/config</code> | 3 | 0 | 0 | 0 |
| <code>/.kube/config.bak</code> | 0 | 0 | 1 | 0 |
| <code>/.netrc</code> | 2 | 0 | 0 | 0 |
| <code>/.npmrc</code> | 4 | 0 | 0 | 0 |
| <code>/.pypirc</code> | 4 | 0 | 0 | 0 |
| <code>/.s3cfg</code> | 2 | 0 | 0 | 0 |
| <code>/.ssh/authorized_keys</code> | 1 | 0 | 0 | 0 |
| <code>/.ssh/config</code> | 1 | 0 | 0 | 0 |
| <code>/.ssh/id_ed25519</code> | 7 | 0 | 0 | 0 |
| <code>/.ssh/id_rsa</code> | 6 | 0 | 2 | 0 |
| <code>/.ssh/id_rsa.pub</code> | 1 | 0 | 0 | 0 |
| <code>/.ssh/{redacted}</code> | 0 | 0 | 3 | 0 |
| <code>/.svn/entries</code> | 12 | 0 | 3 | 0 |
| <code>/.svn/format</code> | 2 | 0 | 0 | 0 |
| <code>/.svn/wc.db</code> | 16 | 0 | 12 | 0 |
| <code>/.vscode/sftp.json</code> | 9 | 0 | 0 | 0 |
| <code>/.well-known/gcp-keys.json</code> | 1 | 0 | 0 | 0 |
| <code>/.well-known/wp-login.php</code> | 0 | 0 | 1 | 0 |
| <code>/.windsurf/auth.json</code> | 1 | 0 | 0 | 0 |
| <code>/.windsurf/mcp.json</code> | 2 | 0 | 0 | 0 |
| <code>//2018/wp-includes/wlwmanifest.xml</code> | 3 | 0 | 0 | 0 |
| <code>//2019/wp-includes/wlwmanifest.xml</code> | 6 | 0 | 0 | 0 |
| <code>//2020/wp-includes/wlwmanifest.xml</code> | 2 | 0 | 0 | 0 |
| <code>//app//etc//local.xml.gz</code> | 1 | 0 | 0 | 0 |
| <code>//assets/images/images/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//blog/.env</code> | 1 | 0 | 0 | 0 |
| <code>//blog/wp-includes/wlwmanifest.xml</code> | 5 | 0 | 0 | 0 |
| <code>//blogs/media/media/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//cache/cache/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//cgi-bin/cgi-bin/cgi-bin/cgi-bin/cache.php</code> | 1 | 0 | 0 | 0 |
| <code>//cms/wp-includes/wlwmanifest.xml</code> | 9 | 0 | 0 | 0 |
| <code>//images/images/images/cache.php</code> | 4 | 0 | 0 | 0 |
| <code>//images/images/images/images/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//images/images/images/images/images/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//images/images/images/images/images/images/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//images/images/images/images/images/images/images/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//images/images/images/images/images/images/images/images/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//media/wp-includes/wlwmanifest.xml</code> | 5 | 0 | 0 | 0 |
| <code>//news/wp-includes/wlwmanifest.xml</code> | 5 | 0 | 0 | 0 |
| <code>//php_info.php</code> | 1 | 0 | 0 | 0 |
| <code>//server/.env</code> | 1 | 0 | 0 | 0 |
| <code>//shop/wp-includes/wlwmanifest.xml</code> | 5 | 0 | 0 | 0 |
| <code>//site/wp-includes/wlwmanifest.xml</code> | 8 | 0 | 0 | 0 |
| <code>//sito/wp-includes/wlwmanifest.xml</code> | 6 | 0 | 0 | 0 |
| <code>//src/.env</code> | 1 | 0 | 0 | 0 |
| <code>//storage/.env</code> | 1 | 0 | 0 | 0 |
| <code>//system/.env</code> | 1 | 0 | 0 | 0 |
| <code>//test/.env</code> | 2 | 0 | 0 | 0 |
| <code>//test/wp-includes/wlwmanifest.xml</code> | 5 | 0 | 0 | 0 |
| <code>//vpnapp/.env</code> | 1 | 0 | 0 | 0 |
| <code>//web/.env</code> | 1 | 0 | 0 | 0 |
| <code>//web/wp-includes/wlwmanifest.xml</code> | 4 | 0 | 0 | 0 |
| <code>//website/wp-includes/wlwmanifest.xml</code> | 4 | 0 | 0 | 0 |
| <code>//wordpress/wp-includes/wlwmanifest.xml</code> | 6 | 0 | 0 | 0 |
| <code>//wp-content/plugins/plugins/cache.php</code> | 5 | 0 | 0 | 0 |
| <code>//wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>//wp/wp-includes/wlwmanifest.xml</code> | 4 | 0 | 0 | 0 |
| <code>//wp1/wp-includes/wlwmanifest.xml</code> | 8 | 0 | 0 | 0 |
| <code>//wp2/wp-includes/wlwmanifest.xml</code> | 6 | 0 | 0 | 0 |
| <code>//www/.env</code> | 1 | 0 | 0 | 0 |
| <code>//xmlrpc.php</code> | 4 | 4 | 6 | 0 |
| <code>/2019/wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>/@vite/env</code> | 2 | 0 | 0 | 0 |
| <code>/CONFIG.JSON.bak</code> | 1 | 0 | 0 | 0 |
| <code>/_phpinfo.php</code> | 1 | 0 | 0 | 0 |
| <code>/_profiler/open</code> | 3 | 0 | 0 | 0 |
| <code>/_profiler/phpinfo</code> | 6 | 0 | 0 | 0 |
| <code>/_profiler/phpinfo.php</code> | 2 | 0 | 0 | 0 |
| <code>/_vti_pvt/service.pwd</code> | 2 | 0 | 0 | 0 |
| <code>/access.log</code> | 1 | 0 | 0 | 0 |
| <code>/actuator//env</code> | 2 | 0 | 0 | 0 |
| <code>/actuator/configprops</code> | 2 | 0 | 6 | 0 |
| <code>/actuator/env</code> | 12 | 0 | 4 | 0 |
| <code>/actuator/heapdump</code> | 4 | 0 | 4 | 0 |
| <code>/actuator/{redacted}</code> | 0 | 0 | 4 | 0 |
| <code>/admin/.env</code> | 0 | 1 | 15 | 0 |
| <code>/admin/.env.production</code> | 0 | 1 | 0 | 0 |
| <code>/admin/.git/config</code> | 2 | 1 | 2 | 0 |
| <code>/admin/config.json</code> | 0 | 0 | 0 | 6 |
| <code>/admin/config.php</code> | 0 | 3 | 0 | 1 |
| <code>/admin/debug</code> | 0 | 2 | 0 | 0 |
| <code>/admin/login/livewire/update</code> | 5 | 2 | 0 | 0 |
| <code>/admin/phpinfo.php</code> | 1 | 2 | 7 | 0 |
| <code>/adminer.php</code> | 2 | 0 | 0 | 0 |
| <code>/administrator/.env</code> | 0 | 0 | 4 | 0 |
| <code>/administrator/phpinfo.php</code> | 3 | 0 | 3 | 0 |
| <code>/api/.env</code> | 8 | 0 | 15 | 0 |
| <code>/api/.env.bak</code> | 0 | 0 | 2 | 0 |
| <code>/api/.env/public/.env</code> | 0 | 0 | 6 | 0 |
| <code>/api/.git/config</code> | 2 | 0 | 2 | 0 |
| <code>/api/config.php</code> | 2 | 0 | 2 | 0 |
| <code>/api/phpinfo.php</code> | 1 | 0 | 4 | 0 |
| <code>/api/shared/config/config.env</code> | 3 | 0 | 0 | 0 |
| <code>/api/v1/.env</code> | 0 | 0 | 7 | 0 |
| <code>/api/v2/.env</code> | 0 | 0 | 8 | 0 |
| <code>/api/v3/.env</code> | 0 | 0 | 8 | 0 |
| <code>/app.py</code> | 1 | 0 | 0 | 0 |
| <code>/app/.env</code> | 4 | 1 | 10 | 0 |
| <code>/app/.git/config</code> | 2 | 0 | 2 | 0 |
| <code>/app/config.php</code> | 0 | 0 | 1 | 0 |
| <code>/app/config/parameters.yml</code> | 1 | 0 | 0 | 0 |
| <code>/application.yml</code> | 1 | 0 | 2 | 0 |
| <code>/application_default_credentials.json</code> | 7 | 0 | 0 | 0 |
| <code>/appsettings.Development.json</code> | 1 | 0 | 0 | 0 |
| <code>/appsettings.Production.json</code> | 3 | 0 | 0 | 0 |
| <code>/appsettings.json</code> | 8 | 0 | 0 | 0 |
| <code>/assets../.git/config</code> | 1 | 1 | 0 | 0 |
| <code>/assets/.env</code> | 0 | 0 | 9 | 0 |
| <code>/assets/credentials.json</code> | 1 | 0 | 0 | 0 |
| <code>/auth.json</code> | 1 | 0 | 0 | 0 |
| <code>/aws.env</code> | 2 | 0 | 0 | 0 |
| <code>/aws/.env</code> | 0 | 0 | 2 | 0 |
| <code>/aws/credentials</code> | 2 | 0 | 0 | 0 |
| <code>/azure-config.json</code> | 2 | 0 | 0 | 0 |
| <code>/azure.json</code> | 2 | 0 | 0 | 0 |
| <code>/backend/%2eenv</code> | 0 | 0 | 1 | 0 |
| <code>/backend/.%65nv</code> | 0 | 0 | 1 | 0 |
| <code>/backend/.env</code> | 4 | 2 | 9 | 0 |
| <code>/backend/.env.production</code> | 0 | 0 | 1 | 0 |
| <code>/backend/.git/config</code> | 2 | 0 | 2 | 0 |
| <code>/backend//.env</code> | 0 | 0 | 1 | 0 |
| <code>/backend/phpinfo.php</code> | 2 | 0 | 0 | 0 |
| <code>/backend/{redacted}/.env</code> | 0 | 0 | 1 | 0 |
| <code>/backup.bak</code> | 1 | 0 | 0 | 0 |
| <code>/backup.env</code> | 1 | 0 | 0 | 0 |
| <code>/backup.sql</code> | 7 | 0 | 7 | 0 |
| <code>/backup.sql.gz</code> | 1 | 0 | 0 | 0 |
| <code>/backup.tar.gz</code> | 7 | 0 | 2 | 0 |
| <code>/backup.zip</code> | 6 | 0 | 2 | 0 |
| <code>/backup/.env</code> | 1 | 0 | 6 | 0 |
| <code>/backup/.git/HEAD</code> | 0 | 0 | 2 | 0 |
| <code>/backup/.git/config</code> | 0 | 0 | 1 | 0 |
| <code>/beta/.env</code> | 1 | 2 | 4 | 0 |
| <code>/blog/wp-includes/js/json2.js</code> | 3 | 0 | 0 | 0 |
| <code>/blog/wp-json/</code> | 4 | 0 | 0 | 0 |
| <code>/blog/wp-login.php</code> | 1 | 0 | 0 | 0 |
| <code>/buildkite/.env</code> | 0 | 1 | 3 | 0 |
| <code>/cache/{redacted}/{redacted}/{redacted}/.env</code> | 0 | 0 | 6 | 0 |
| <code>/cgi-bin/phpinfo.php</code> | 1 | 0 | 0 | 0 |
| <code>/cgi-bin/wp-login.php</code> | 0 | 0 | 1 | 0 |
| <code>/client/.env</code> | 1 | 0 | 5 | 0 |
| <code>/cms/.env</code> | 0 | 0 | 15 | 0 |
| <code>/cms/wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>/cms/wp-json/</code> | 9 | 0 | 0 | 0 |
| <code>/cms/wp-json/batch/v1</code> | 1 | 0 | 0 | 0 |
| <code>/config.bak</code> | 1 | 0 | 0 | 0 |
| <code>/config.env</code> | 1 | 0 | 0 | 0 |
| <code>/config.json</code> | 18 | 0 | 8 | 0 |
| <code>/config.php</code> | 4 | 0 | 5 | 0 |
| <code>/config.php.bak</code> | 3 | 0 | 9 | 0 |
| <code>/config.php.old</code> | 1 | 0 | 0 | 0 |
| <code>/config.py</code> | 1 | 0 | 0 | 0 |
| <code>/config.xml</code> | 3 | 0 | 0 | 0 |
| <code>/config.yaml</code> | 6 | 0 | 2 | 0 |
| <code>/config.yml</code> | 3 | 0 | 7 | 0 |
| <code>/config/.env</code> | 4 | 2 | 12 | 0 |
| <code>/config/.env.dev</code> | 0 | 0 | 2 | 0 |
| <code>/config/.env.local</code> | 0 | 0 | 2 | 0 |
| <code>/config/app/.env</code> | 0 | 1 | 0 | 0 |
| <code>/config/application.yml</code> | 2 | 0 | 0 | 0 |
| <code>/config/azure.json</code> | 2 | 0 | 0 | 0 |
| <code>/config/bootstrap.properties</code> | 1 | 0 | 0 | 0 |
| <code>/config/bootstrap.yml</code> | 1 | 0 | 0 | 0 |
| <code>/config/config.json</code> | 0 | 0 | 3 | 0 |
| <code>/config/config.php</code> | 0 | 0 | 1 | 0 |
| <code>/config/config.yml</code> | 1 | 0 | 0 | 0 |
| <code>/config/credentials.json</code> | 1 | 0 | 0 | 0 |
| <code>/config/gcp-credentials.json</code> | 0 | 0 | 7 | 0 |
| <code>/config/grafana.ini</code> | 1 | 0 | 0 | 0 |
| <code>/config/kibana.yml</code> | 1 | 0 | 0 | 0 |
| <code>/config/log4j.properties</code> | 1 | 0 | 0 | 0 |
| <code>/config/log4j2.xml</code> | 1 | 0 | 0 | 0 |
| <code>/config/logstash.yml</code> | 1 | 0 | 0 | 0 |
| <code>/config/mongod.conf</code> | 1 | 0 | 0 | 0 |
| <code>/config/nginx.conf</code> | 1 | 0 | 0 | 0 |
| <code>/config/secrets.json</code> | 2 | 0 | 0 | 0 |
| <code>/config/tomcat-users.xml</code> | 1 | 0 | 0 | 0 |
| <code>/configuration.php</code> | 2 | 0 | 0 | 0 |
| <code>/content../.git/config</code> | 0 | 1 | 0 | 0 |
| <code>/core/.env</code> | 0 | 0 | 15 | 0 |
| <code>/core/app/.env</code> | 0 | 0 | 1 | 0 |
| <code>/core/phpinfo.php</code> | 3 | 0 | 0 | 0 |
| <code>/credentials.ini</code> | 1 | 0 | 0 | 0 |
| <code>/credentials.json</code> | 10 | 0 | 7 | 0 |
| <code>/crm/.env</code> | 1 | 0 | 1 | 0 |
| <code>/css../.git/config</code> | 1 | 1 | 0 | 0 |
| <code>/data/.env</code> | 0 | 0 | 2 | 0 |
| <code>/data/credentials.json</code> | 1 | 0 | 0 | 0 |
| <code>/database.php.bak</code> | 2 | 0 | 1 | 0 |
| <code>/database.sql</code> | 9 | 0 | 4 | 0 |
| <code>/database_backup.sql</code> | 2 | 0 | 1 | 0 |
| <code>/db.php</code> | 1 | 0 | 0 | 0 |
| <code>/db.sql</code> | 6 | 0 | 4 | 0 |
| <code>/debug.log</code> | 1 | 0 | 0 | 0 |
| <code>/debug.php</code> | 1 | 0 | 0 | 0 |
| <code>/debug/default/view</code> | 2 | 0 | 0 | 0 |
| <code>/debug/phpinfo.php</code> | 1 | 0 | 0 | 0 |
| <code>/demo/.env</code> | 2 | 0 | 2 | 0 |
| <code>/deploy/.env</code> | 2 | 1 | 6 | 0 |
| <code>/dev/.env</code> | 1 | 0 | 8 | 0 |
| <code>/dev/phpinfo.php</code> | 1 | 0 | 4 | 0 |
| <code>/development/.env</code> | 1 | 1 | 0 | 0 |
| <code>/docker-compose.yml</code> | 4 | 0 | 0 | 0 |
| <code>/docs/phpinfo.php</code> | 4 | 0 | 2 | 0 |
| <code>/dump.sql</code> | 7 | 0 | 6 | 0 |
| <code>/dump.sql.gz</code> | 2 | 0 | 0 | 0 |
| <code>/email/.env</code> | 0 | 0 | 6 | 0 |
| <code>/env</code> | 1 | 0 | 0 | 0 |
| <code>/error.log</code> | 3 | 0 | 0 | 0 |
| <code>/error_log</code> | 1 | 0 | 0 | 0 |
| <code>/events../.git/config</code> | 1 | 1 | 0 | 0 |
| <code>/firebase-adminsdk.json</code> | 7 | 0 | 0 | 0 |
| <code>/firebase-key.json</code> | 4 | 0 | 0 | 0 |
| <code>/frontend/.env</code> | 0 | 1 | 9 | 0 |
| <code>/frontend/.git/config</code> | 2 | 0 | 2 | 0 |
| <code>/functions.php</code> | 1 | 0 | 0 | 0 |
| <code>/gcp-credentials.json</code> | 12 | 0 | 9 | 0 |
| <code>/gcp-key.json</code> | 6 | 0 | 0 | 0 |
| <code>/gcp-sa.json</code> | 3 | 0 | 0 | 0 |
| <code>/gcp-service-account.json</code> | 1 | 0 | 0 | 0 |
| <code>/google-credentials.json</code> | 6 | 0 | 0 | 0 |
| <code>/google-key.json</code> | 3 | 0 | 0 | 0 |
| <code>/hosting/phpinfo.php</code> | 2 | 0 | 3 | 0 |
| <code>/htdocs/.env</code> | 0 | 1 | 2 | 0 |
| <code>/htdocs/phpinfo.php</code> | 3 | 0 | 3 | 0 |
| <code>/id_dsa</code> | 1 | 0 | 0 | 0 |
| <code>/id_rsa</code> | 2 | 0 | 0 | 0 |
| <code>/img../.git/config</code> | 0 | 1 | 0 | 0 |
| <code>/includes/config.php</code> | 0 | 0 | 1 | 0 |
| <code>/includes/phpinfo.php</code> | 5 | 0 | 3 | 0 |
| <code>/index.php</code> | 15 | 0 | 0 | 0 |
| <code>/info.php</code> | 9 | 0 | 0 | 0 |
| <code>/info.php.bak</code> | 2 | 0 | 2 | 0 |
| <code>/job/.env</code> | 0 | 1 | 0 | 0 |
| <code>/js../.git/config</code> | 1 | 1 | 0 | 0 |
| <code>/kafka/.env</code> | 1 | 1 | 0 | 0 |
| <code>/key.json</code> | 4 | 0 | 0 | 0 |
| <code>/keyfile.json</code> | 6 | 0 | 0 | 0 |
| <code>/lab/.env</code> | 1 | 0 | 9 | 0 |
| <code>/laravel/.env</code> | 2 | 0 | 10 | 0 |
| <code>/laravel/.env.backup</code> | 1 | 0 | 0 | 0 |
| <code>/laravel/api-keys</code> | 1 | 0 | 0 | 0 |
| <code>/laravel/cadastro</code> | 1 | 0 | 0 | 0 |
| <code>/laravel/painel</code> | 1 | 0 | 0 | 0 |
| <code>/laravel/setup</code> | 1 | 0 | 0 | 0 |
| <code>/laravel/subscription</code> | 1 | 0 | 0 | 0 |
| <code>/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php</code> | 0 | 1 | 0 | 0 |
| <code>/laravel/webhooks</code> | 1 | 0 | 0 | 0 |
| <code>/laravel/welcome</code> | 1 | 0 | 0 | 0 |
| <code>/laravel/workspace</code> | 1 | 0 | 0 | 0 |
| <code>/lib../.git/config</code> | 1 | 0 | 0 | 0 |
| <code>/lib/.env</code> | 0 | 0 | 13 | 0 |
| <code>/lib/config.php</code> | 0 | 0 | 1 | 0 |
| <code>/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php</code> | 0 | 1 | 0 | 0 |
| <code>/livewire/update</code> | 9 | 0 | 0 | 0 |
| <code>/local.settings.json</code> | 2 | 0 | 0 | 0 |
| <code>/logs/</code> | 1 | 0 | 0 | 0 |
| <code>/logs/.env</code> | 0 | 0 | 2 | 0 |
| <code>/logs/error.log</code> | 2 | 0 | 0 | 0 |
| <code>/mail/.env</code> | 0 | 0 | 1 | 0 |
| <code>/mail/phpinfo.php</code> | 2 | 0 | 2 | 0 |
| <code>/main/wp-json/batch/v1</code> | 1 | 0 | 0 | 0 |
| <code>/main/wp-login.php</code> | 2 | 0 | 0 | 0 |
| <code>/media../.git/config</code> | 0 | 1 | 0 | 0 |
| <code>/media/.env</code> | 0 | 0 | 2 | 0 |
| <code>/mongodb/.env</code> | 0 | 1 | 0 | 0 |
| <code>/mysql/.env</code> | 0 | 1 | 4 | 0 |
| <code>/mysql/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/new/wp-includes/js/json2.js</code> | 3 | 0 | 0 | 0 |
| <code>/new/wp-json/</code> | 1 | 0 | 0 | 0 |
| <code>/new/wp-json/batch/v1</code> | 1 | 0 | 0 | 0 |
| <code>/news/wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>/news/wp-json/</code> | 8 | 0 | 0 | 0 |
| <code>/newsletter/.env</code> | 0 | 0 | 2 | 0 |
| <code>/next.config.js</code> | 1 | 0 | 0 | 0 |
| <code>/old/.env</code> | 0 | 1 | 2 | 0 |
| <code>/old/.git/HEAD</code> | 0 | 0 | 1 | 0 |
| <code>/old/.git/config</code> | 0 | 0 | 1 | 0 |
| <code>/old/phpinfo.php</code> | 2 | 0 | 0 | 0 |
| <code>/old/wp-includes/js/json2.js</code> | 3 | 0 | 0 | 0 |
| <code>/old/wp-json/</code> | 1 | 0 | 0 | 0 |
| <code>/old_phpinfo.php</code> | 2 | 0 | 0 | 0 |
| <code>/p.php</code> | 1 | 0 | 0 | 0 |
| <code>/php-info.php</code> | 1 | 0 | 0 | 0 |
| <code>/php/login.php</code> | 2 | 0 | 0 | 0 |
| <code>/php_info.php</code> | 4 | 0 | 0 | 0 |
| <code>/phpinfo</code> | 3 | 0 | 0 | 0 |
| <code>/phpinfo.php</code> | 17 | 0 | 19 | 0 |
| <code>/phpinfo.php.bak</code> | 3 | 0 | 0 | 0 |
| <code>/phpinfo.php.old</code> | 4 | 0 | 0 | 0 |
| <code>/phpinfo/index.php</code> | 1 | 0 | 0 | 0 |
| <code>/phpinfo/test.php</code> | 1 | 0 | 0 | 0 |
| <code>/phpmyadmin/</code> | 0 | 1 | 0 | 0 |
| <code>/phpversion.php</code> | 3 | 0 | 0 | 0 |
| <code>/postgres/.env</code> | 0 | 0 | 2 | 0 |
| <code>/postgres/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/postmark/.env</code> | 1 | 0 | 1 | 0 |
| <code>/ppinfo.php</code> | 1 | 0 | 0 | 0 |
| <code>/press/wp-json/</code> | 7 | 0 | 0 | 0 |
| <code>/preview/.env</code> | 1 | 2 | 0 | 0 |
| <code>/preview/phpinfo.php</code> | 3 | 0 | 0 | 0 |
| <code>/private.key</code> | 2 | 0 | 0 | 0 |
| <code>/production/.env</code> | 1 | 1 | 5 | 0 |
| <code>/public/.env</code> | 0 | 0 | 8 | 0 |
| <code>/public/.git/HEAD</code> | 0 | 0 | 1 | 0 |
| <code>/public/.git/config</code> | 0 | 0 | 2 | 0 |
| <code>/public/config.js</code> | 1 | 0 | 0 | 0 |
| <code>/public/phpinfo.php</code> | 1 | 0 | 3 | 0 |
| <code>/public_html/.env</code> | 0 | 0 | 3 | 0 |
| <code>/public_html/phpinfo.php</code> | 3 | 0 | 0 | 0 |
| <code>/qa/.env</code> | 1 | 1 | 1 | 0 |
| <code>/qa/phpinfo.php</code> | 4 | 0 | 0 | 0 |
| <code>/queue/.env</code> | 1 | 0 | 0 | 0 |
| <code>/rabbitmq/.env</code> | 1 | 1 | 2 | 0 |
| <code>/react/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/redis/.env</code> | 0 | 2 | 0 | 0 |
| <code>/register/livewire/update</code> | 5 | 0 | 0 | 0 |
| <code>/s/{opaque-002}/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties</code> | 3 | 0 | 0 | 0 |
| <code>/s/{opaque-005}/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties</code> | 2 | 0 | 0 | 0 |
| <code>/sa.json</code> | 5 | 0 | 0 | 0 |
| <code>/secret/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/secrets.json</code> | 6 | 0 | 0 | 0 |
| <code>/secrets/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/secrets/credentials.json</code> | 1 | 0 | 0 | 0 |
| <code>/sender/.env</code> | 1 | 0 | 0 | 0 |
| <code>/server-info.php</code> | 1 | 0 | 0 | 0 |
| <code>/server-status</code> | 0 | 7 | 0 | 3 |
| <code>/server-status.php</code> | 2 | 2 | 0 | 0 |
| <code>/server.key</code> | 5 | 0 | 0 | 0 |
| <code>/server/.env</code> | 1 | 0 | 7 | 0 |
| <code>/server/.git/config</code> | 2 | 0 | 2 | 0 |
| <code>/server/credentials.json</code> | 1 | 0 | 0 | 0 |
| <code>/server_info.php</code> | 1 | 0 | 0 | 0 |
| <code>/service-account.json</code> | 4 | 0 | 0 | 0 |
| <code>/service_account.json</code> | 3 | 0 | 0 | 0 |
| <code>/settings.json</code> | 3 | 0 | 2 | 0 |
| <code>/settings.php</code> | 3 | 0 | 2 | 0 |
| <code>/settings.py</code> | 3 | 0 | 0 | 0 |
| <code>/shared/.env</code> | 0 | 0 | 2 | 0 |
| <code>/shop/.env</code> | 0 | 0 | 3 | 0 |
| <code>/site.zip</code> | 3 | 0 | 0 | 0 |
| <code>/site/.env</code> | 0 | 1 | 5 | 0 |
| <code>/site/phpinfo.php</code> | 5 | 0 | 2 | 0 |
| <code>/site/wp-admin/</code> | 0 | 0 | 1 | 0 |
| <code>/site/wp-json/</code> | 4 | 0 | 0 | 0 |
| <code>/site/wp-json/batch/v1</code> | 1 | 0 | 0 | 0 |
| <code>/site/wp-login.php</code> | 2 | 0 | 0 | 0 |
| <code>/sitemaps/.env</code> | 1 | 0 | 2 | 0 |
| <code>/sites/default/config.php</code> | 1 | 0 | 0 | 0 |
| <code>/sites/default/settings.php</code> | 1 | 0 | 1 | 0 |
| <code>/sites/default/{redacted}</code> | 0 | 0 | 1 | 0 |
| <code>/sito/wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>/smtp/phpinfo.php</code> | 1 | 0 | 4 | 0 |
| <code>/src/.env</code> | 0 | 0 | 8 | 0 |
| <code>/src/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/stage/.env</code> | 1 | 0 | 4 | 0 |
| <code>/staging/.env</code> | 0 | 0 | 10 | 0 |
| <code>/staging/phpinfo.php</code> | 2 | 0 | 0 | 0 |
| <code>/static/.env</code> | 0 | 0 | 6 | 0 |
| <code>/static/app/.env</code> | 0 | 0 | 1 | 0 |
| <code>/static/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/storage/.env</code> | 0 | 0 | 5 | 0 |
| <code>/storage/credentials.json</code> | 1 | 0 | 0 | 0 |
| <code>/storage/logs/laravel.log</code> | 4 | 0 | 0 | 0 |
| <code>/store/.env</code> | 0 | 1 | 6 | 0 |
| <code>/stripe/.env</code> | 1 | 1 | 0 | 0 |
| <code>/studioserver/.git/config</code> | 2 | 0 | 2 | 0 |
| <code>/system-info.php</code> | 1 | 0 | 0 | 0 |
| <code>/telescope/api/requests</code> | 1 | 0 | 0 | 0 |
| <code>/telescope/requests</code> | 2 | 0 | 0 | 0 |
| <code>/test.php</code> | 3 | 0 | 0 | 0 |
| <code>/test/.env</code> | 1 | 1 | 0 | 0 |
| <code>/test/phpinfo.php</code> | 2 | 0 | 2 | 0 |
| <code>/test/wp-includes/js/json2.js</code> | 3 | 0 | 0 | 0 |
| <code>/tmp/.env</code> | 0 | 0 | 4 | 0 |
| <code>/tmp/phpinfo.php</code> | 1 | 0 | 5 | 0 |
| <code>/trace.axd</code> | 2 | 0 | 0 | 0 |
| <code>/uat/.env</code> | 0 | 1 | 0 | 0 |
| <code>/uat/phpinfo.php</code> | 1 | 0 | 0 | 0 |
| <code>/uploads/.env</code> | 0 | 0 | 2 | 0 |
| <code>/user_secrets.yml</code> | 1 | 0 | 0 | 0 |
| <code>/v1/.env</code> | 0 | 0 | 8 | 0 |
| <code>/v2/.env</code> | 1 | 0 | 9 | 0 |
| <code>/v2/api-docs</code> | 1 | 0 | 0 | 0 |
| <code>/v3/.env</code> | 0 | 0 | 1 | 0 |
| <code>/v3/api-docs</code> | 1 | 0 | 0 | 0 |
| <code>/var/log/nginx/error.log</code> | 2 | 0 | 0 | 0 |
| <code>/var/www/.env</code> | 1 | 2 | 3 | 0 |
| <code>/var/www/{redacted}/.env</code> | 0 | 0 | 1 | 0 |
| <code>/vendor/.env</code> | 0 | 0 | 2 | 0 |
| <code>/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php</code> | 0 | 1 | 0 | 0 |
| <code>/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php</code> | 0 | 1 | 0 | 0 |
| <code>/vertex-key.json</code> | 1 | 0 | 0 | 0 |
| <code>/vite.config.js</code> | 2 | 0 | 0 | 0 |
| <code>/vite.config.ts</code> | 2 | 0 | 0 | 0 |
| <code>/vue.config.js</code> | 1 | 0 | 0 | 0 |
| <code>/vue/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/web.config</code> | 5 | 0 | 4 | 0 |
| <code>/web.config.bak</code> | 1 | 0 | 0 | 0 |
| <code>/web/.env</code> | 1 | 0 | 8 | 0 |
| <code>/web/.git/config</code> | 2 | 0 | 2 | 0 |
| <code>/web/wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>/webmail/phpinfo.php</code> | 1 | 0 | 3 | 0 |
| <code>/webpack.config.js</code> | 1 | 0 | 0 | 0 |
| <code>/webroot/index.php/_environment</code> | 2 | 0 | 0 | 0 |
| <code>/website/.env</code> | 1 | 0 | 0 | 0 |
| <code>/website/wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>/webstats/awstats.pl</code> | 1 | 0 | 0 | 0 |
| <code>/wordpress/</code> | 11 | 0 | 0 | 0 |
| <code>/wordpress/.env</code> | 0 | 0 | 4 | 0 |
| <code>/wordpress/wp-includes/js/json2.js</code> | 3 | 0 | 0 | 0 |
| <code>/wordpress/wp-json/</code> | 9 | 0 | 0 | 0 |
| <code>/worker/.env</code> | 1 | 1 | 0 | 0 |
| <code>/workspace/.env</code> | 0 | 0 | 1 | 0 |
| <code>/wp-admin/</code> | 5 | 1 | 2 | 0 |
| <code>/wp-admin/css/</code> | 0 | 1 | 0 | 0 |
| <code>/wp-admin/css/{redacted}/wp-login.php</code> | 0 | 0 | 2 | 0 |
| <code>/wp-admin/images/</code> | 0 | 1 | 0 | 0 |
| <code>/wp-admin/includes/</code> | 0 | 1 | 0 | 0 |
| <code>/wp-admin/index.php</code> | 1 | 0 | 0 | 0 |
| <code>/wp-admin/js/</code> | 0 | 1 | 0 | 0 |
| <code>/wp-admin/maint/</code> | 0 | 1 | 0 | 0 |
| <code>/wp-admin/network/</code> | 0 | 1 | 0 | 0 |
| <code>/wp-admin/phpinfo.php</code> | 1 | 0 | 0 | 0 |
| <code>/wp-admin/setup-config.php</code> | 4 | 0 | 0 | 0 |
| <code>/wp-admin/user/</code> | 0 | 1 | 0 | 0 |
| <code>/wp-admin/user/wp-login.php</code> | 0 | 0 | 1 | 0 |
| <code>/wp-config.bak</code> | 1 | 0 | 0 | 0 |
| <code>/wp-config.old</code> | 1 | 0 | 3 | 0 |
| <code>/wp-config.php</code> | 14 | 0 | 6 | 0 |
| <code>/wp-config.php-backup</code> | 2 | 0 | 0 | 0 |
| <code>/wp-config.php-save</code> | 2 | 0 | 0 | 0 |
| <code>/wp-config.php.bak</code> | 8 | 0 | 9 | 0 |
| <code>/wp-config.php.dist</code> | 2 | 0 | 0 | 0 |
| <code>/wp-config.php.gz</code> | 1 | 0 | 0 | 0 |
| <code>/wp-config.php.old</code> | 2 | 0 | 6 | 0 |
| <code>/wp-config.php.orig</code> | 2 | 0 | 0 | 0 |
| <code>/wp-config.php.save</code> | 5 | 0 | 0 | 0 |
| <code>/wp-config.php.swp</code> | 1 | 0 | 0 | 0 |
| <code>/wp-config.php.zip</code> | 2 | 0 | 0 | 0 |
| <code>/wp-config.php~</code> | 2 | 0 | 0 | 0 |
| <code>/wp-config.txt</code> | 1 | 0 | 0 | 0 |
| <code>/wp-content/</code> | 0 | 0 | 1 | 0 |
| <code>/wp-content/mysql.bak</code> | 1 | 0 | 0 | 0 |
| <code>/wp-content/plugins/easy-google-fonts/error_log</code> | 2 | 0 | 0 | 0 |
| <code>/wp-content/plugins/newsletter/error_log</code> | 1 | 0 | 0 | 0 |
| <code>/wp-content/plugins/wordpress-importer/error_log</code> | 1 | 0 | 0 | 0 |
| <code>/wp-content/plugins/wps-hide-login/classes/error_log</code> | 1 | 0 | 0 | 0 |
| <code>/wp-content/uploads/credentials.json</code> | 1 | 0 | 0 | 0 |
| <code>/wp-content/uploads/dump.bak</code> | 1 | 0 | 0 | 0 |
| <code>/wp-content/{redacted}/wp-login.php</code> | 0 | 0 | 2 | 0 |
| <code>/wp-includes/</code> | 2 | 0 | 2 | 0 |
| <code>/wp-includes/images/wp-login.php</code> | 0 | 0 | 1 | 0 |
| <code>/wp-includes/js/json2.js</code> | 3 | 0 | 0 | 0 |
| <code>/wp-includes/js/wp-emoji-release.min.js</code> | 1 | 0 | 0 | 0 |
| <code>/wp-includes/style.php</code> | 2 | 0 | 0 | 0 |
| <code>/wp-includes/version.php</code> | 2 | 0 | 0 | 0 |
| <code>/wp-includes/{redacted}/wp-login.php</code> | 0 | 0 | 2 | 0 |
| <code>/wp-json</code> | 0 | 0 | 2 | 0 |
| <code>/wp-json/</code> | 11 | 0 | 1 | 0 |
| <code>/wp-json/batch%2fv1</code> | 1 | 0 | 0 | 0 |
| <code>/wp-json/batch/v1</code> | 21 | 0 | 0 | 0 |
| <code>/wp-json/gravitysmtp/v1/tests/mock-data</code> | 1 | 0 | 0 | 0 |
| <code>/wp-json/mcp/v1</code> | 1 | 0 | 0 | 0 |
| <code>/wp-json/wp/v2/pages</code> | 1 | 0 | 0 | 0 |
| <code>/wp-json/wp/v2/posts</code> | 1 | 0 | 0 | 0 |
| <code>/wp-json/wp/v2/users</code> | 1 | 0 | 0 | 0 |
| <code>/wp-login.php</code> | 15 | 3 | 7 | 0 |
| <code>/wp/</code> | 12 | 0 | 0 | 0 |
| <code>/wp/.env</code> | 0 | 0 | 10 | 0 |
| <code>/wp/v2/blocks</code> | 5 | 0 | 0 | 0 |
| <code>/wp/v2/categories</code> | 1 | 0 | 0 | 0 |
| <code>/wp/v2/comments</code> | 3 | 0 | 0 | 0 |
| <code>/wp/v2/media</code> | 1 | 0 | 0 | 0 |
| <code>/wp/v2/pages</code> | 1 | 0 | 0 | 0 |
| <code>/wp/v2/posts/999999</code> | 1 | 0 | 0 | 0 |
| <code>/wp/v2/template-parts</code> | 5 | 0 | 0 | 0 |
| <code>/wp/v2/templates</code> | 5 | 0 | 0 | 0 |
| <code>/wp/v2/users</code> | 2 | 0 | 0 | 0 |
| <code>/wp/v2/widgets</code> | 2 | 0 | 0 | 0 |
| <code>/wp/wp-includes/js/json2.js</code> | 3 | 0 | 0 | 0 |
| <code>/wp/wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>/wp/wp-json/</code> | 7 | 0 | 0 | 0 |
| <code>/wp/wp-json/batch/v1</code> | 1 | 0 | 0 | 0 |
| <code>/wp1/wp-includes/wlwmanifest.xml</code> | 1 | 0 | 0 | 0 |
| <code>/wrangler.json</code> | 1 | 0 | 0 | 0 |
| <code>/wrangler.toml</code> | 1 | 0 | 0 | 0 |
| <code>/www.zip</code> | 1 | 0 | 0 | 0 |
| <code>/www/.env</code> | 0 | 1 | 4 | 0 |
| <code>/www/.git/config</code> | 2 | 0 | 2 | 0 |
| <code>/www/phpinfo.php</code> | 3 | 0 | 1 | 0 |
| <code>/xmlrpc.php</code> | 9 | 1 | 1 | 0 |
| <code>/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php</code> | 0 | 1 | 0 | 0 |
| <code>/zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php</code> | 0 | 1 | 0 | 0 |
| <code>/zipkin/config.json</code> | 1 | 0 | 0 | 0 |
| <code>/{redacted}</code> | 0 | 0 | 194 | 0 |
| <code>/{redacted}/</code> | 0 | 0 | 0 | 1 |
| <code>/{redacted}/.env</code> | 0 | 0 | 362 | 0 |
| <code>/{redacted}/.env.dev</code> | 0 | 0 | 1 | 0 |
| <code>/{redacted}/.env.local</code> | 0 | 0 | 1 | 0 |
| <code>/{redacted}/.env.staging</code> | 0 | 0 | 1 | 0 |
| <code>/{redacted}/.git/HEAD</code> | 0 | 0 | 1 | 0 |
| <code>/{redacted}/HEAD</code> | 0 | 0 | 0 | 1 |
| <code>/{redacted}/_profiler</code> | 0 | 0 | 1 | 0 |
| <code>/{redacted}/admin/.env</code> | 0 | 0 | 1 | 0 |
| <code>/{redacted}/api/.env</code> | 0 | 0 | 9 | 0 |
| <code>/{redacted}/cache/.env.php</code> | 0 | 0 | 1 | 0 |
| <code>/{redacted}/cache/config.php</code> | 0 | 0 | 2 | 0 |
| <code>/{redacted}/config.json</code> | 0 | 0 | 2 | 0 |
| <code>/{redacted}/config.php</code> | 0 | 0 | 2 | 0 |
| <code>/{redacted}/config.yml</code> | 0 | 0 | 3 | 0 |
| <code>/{redacted}/docs/.env</code> | 0 | 0 | 3 | 0 |
| <code>/{redacted}/phpinfo.php</code> | 0 | 0 | 2 | 0 |
| <code>/{redacted}/settings.json</code> | 0 | 0 | 4 | 0 |
| <code>/{redacted}/web/.env</code> | 0 | 0 | 2 | 0 |
| <code>/{redacted}/{redacted}</code> | 0 | 0 | 1 | 2 |
| <code>/{redacted}/{redacted}/.env</code> | 0 | 0 | 4 | 0 |
| <code>/~/.aws/config</code> | 1 | 0 | 0 | 0 |
| **Total** | **1,537** | **143** | **1,680** | **14** |

</details>

### Using the register

Keep credentials, repository metadata and backups outside the served document root. Deny confirmed nonpublic targets at both CDN and origin.

Validate each path against the site's intended public routes before implementing a rule. Public configuration files and environment examples may be intentional. Preserve working APIs and required well-known resources. Verify normalization, denial responses and rollback with controlled fixtures.

## Scanner target update, 12–17 November

The original daily path queries for 15 and 16 November reached the 350-group cap. The table below replaces those two daily results with 48 disjoint one-hour queries collected on 20 November. These replace the earlier six-hour estimates rather than being added to them. The historical diagnostic register above uses a separate collection method.

| Target family | Reported Block count | Reported Managed Challenge count |
|---|---:|---:|
| Environment files (/.env and variants) | 1,253 | 0 |
| Version control (/.git/config, /.git/HEAD, /.svn/wc.db) | 101 | 0 |
| Diagnostic endpoints (/actuator/env, /phpinfo.php) | 91 | 3 |
| Database dumps and backups (/db.sql, /config.json.bak) | 77 | 4 |
| Configuration files (/config.json, /api/config.php) | 72 | 7 |
| Cloud or SSH credentials (/.aws/credentials, /.ssh/id_*) | 47 | 0 |
| WordPress probes (/wp-login.php, /wp-config.php, /wp-json/) | 39 | 0 |

None of the 48 replacement hourly queries reached the cap; the largest returned 226 groups. Adaptive sampling was reported in 8 of those 48 intervals and 12 of all 52 retained path intervals. Shorter sampled queries can return different estimates and omit paths seen in earlier queries; this is not evidence of a traffic change. The independent action totals and daily chart are unchanged. [Cloudflare Security Events sampling](https://developers.cloudflare.com/waf/analytics/security-events/#sampling)

### Detailed paths in the returned sample

The consolidated register includes every returned group accepted by the seven-family supplemental filter. **235 distinct public paths or aliases** account for **1,680 Blocks** and **14 Managed Challenges** in this filtered query. Known technical segments preserve their observed case and percent encoding. Other segments appear as `{redacted}`; counts are combined when multiple paths map to the same alias. Routine routes are excluded. Redacted groups account for 622 Blocks and 4 Managed Challenges.

| UTC interval | Returned action/path groups | Distinct qualifying paths in that interval | Query cap reached |
|---|---:|---:|---|
| 2026-11-12 18:00–24:00 | 61 | 28 | No |
| 2026-11-13 00:00–24:00 | 235 | 102 | No |
| 2026-11-14 00:00–24:00 | 166 | 74 | No |
| 2026-11-15 00:00–01:00 | 1 | 0 | No |
| 2026-11-15 01:00–02:00 | 0 | 0 | No |
| 2026-11-15 02:00–03:00 | 1 | 0 | No |
| 2026-11-15 03:00–04:00 | 72 | 40 | No |
| 2026-11-15 04:00–05:00 | 1 | 1 | No |
| 2026-11-15 05:00–06:00 | 2 | 1 | No |
| 2026-11-15 06:00–07:00 | 0 | 0 | No |
| 2026-11-15 07:00–08:00 | 0 | 0 | No |
| 2026-11-15 08:00–09:00 | 0 | 0 | No |
| 2026-11-15 09:00–10:00 | 0 | 0 | No |
| 2026-11-15 10:00–11:00 | 1 | 0 | No |
| 2026-11-15 11:00–12:00 | 0 | 0 | No |
| 2026-11-15 12:00–13:00 | 121 | 38 | No |
| 2026-11-15 13:00–14:00 | 0 | 0 | No |
| 2026-11-15 14:00–15:00 | 1 | 0 | No |
| 2026-11-15 15:00–16:00 | 0 | 0 | No |
| 2026-11-15 16:00–17:00 | 1 | 0 | No |
| 2026-11-15 17:00–18:00 | 0 | 0 | No |
| 2026-11-15 18:00–19:00 | 0 | 0 | No |
| 2026-11-15 19:00–20:00 | 1 | 1 | No |
| 2026-11-15 20:00–21:00 | 28 | 17 | No |
| 2026-11-15 21:00–22:00 | 18 | 1 | No |
| 2026-11-15 22:00–23:00 | 226 | 89 | No |
| 2026-11-15 23:00–24:00 | 33 | 1 | No |
| 2026-11-16 00:00–01:00 | 0 | 0 | No |
| 2026-11-16 01:00–02:00 | 20 | 2 | No |
| 2026-11-16 02:00–03:00 | 1 | 0 | No |
| 2026-11-16 03:00–04:00 | 1 | 1 | No |
| 2026-11-16 04:00–05:00 | 0 | 0 | No |
| 2026-11-16 05:00–06:00 | 0 | 0 | No |
| 2026-11-16 06:00–07:00 | 0 | 0 | No |
| 2026-11-16 07:00–08:00 | 6 | 3 | No |
| 2026-11-16 08:00–09:00 | 30 | 1 | No |
| 2026-11-16 09:00–10:00 | 1 | 0 | No |
| 2026-11-16 10:00–11:00 | 0 | 0 | No |
| 2026-11-16 11:00–12:00 | 1 | 1 | No |
| 2026-11-16 12:00–13:00 | 103 | 90 | No |
| 2026-11-16 13:00–14:00 | 0 | 0 | No |
| 2026-11-16 14:00–15:00 | 0 | 0 | No |
| 2026-11-16 15:00–16:00 | 147 | 51 | No |
| 2026-11-16 16:00–17:00 | 3 | 1 | No |
| 2026-11-16 17:00–18:00 | 1 | 0 | No |
| 2026-11-16 18:00–19:00 | 0 | 0 | No |
| 2026-11-16 19:00–20:00 | 14 | 0 | No |
| 2026-11-16 20:00–21:00 | 0 | 0 | No |
| 2026-11-16 21:00–22:00 | 80 | 46 | No |
| 2026-11-16 22:00–23:00 | 2 | 2 | No |
| 2026-11-16 23:00–24:00 | 0 | 0 | No |
| 2026-11-17 00:00–24:00 | 233 | 145 | No |

A path can appear in multiple intervals. The consolidated register above combines identical public paths and aliases across all intervals.

The consolidated register above includes these update paths once, alongside the historical sample. Its separate columns preserve the two collection methods; they must not be added to the headline action totals.

## Unexpected-port probes

A separately investigated 30-hour window, **10 November 2026, 14:08 UTC–11 November 2026, 20:08 UTC**, recorded six requests addressed to unexpected web ports.

| Requested port | Observed requests | Edge status | Origin HTTP status recorded |
|---:|---:|---:|---|
| 2052 | 1 | 403 | None |
| 2053 | 1 | 403 | None |
| 2082 | 1 | 403 | None |
| 2086 | 1 | 403 | None |
| 2095 | 1 | 403 | None |
| 8880 | 1 | 403 | None |
| **Total** | **6** | | |

These six ports are among the alternative HTTP/HTTPS ports proxied by Cloudflare. Ports 2082, 2086 and 2095 are also conventionally used by cPanel, WHM and webmail, respectively. The pattern is consistent with reconnaissance for hosting control panels, although the requested port alone does not establish the operator's intent. [Cloudflare port reference](https://developers.cloudflare.com/fundamentals/reference/network-ports/) · [cPanel port reference](https://docs.cpanel.net/knowledge-base/general-systems-administration/how-to-configure-your-firewall-for-cpanel-services/).

All six requests were refused at Cloudflare and have no recorded origin HTTP response. These port numbers were observed in the request authority; they are not a packet-level port-scan capture.

This incident is part of the overall observation period and must not be added again to the total Block count. The port-specific window is a limited case study, not an exhaustive count of all port probes in the archive. A separate origin check found no listeners or container port publications for these six ports; external connection tests timed out.

## What the observations support

The diagnostic record contains recurring attempts to locate credentials, configuration files, database exports, backup artifacts and endpoints for software unrelated to the deployed application. The defense responded at the request boundary and was subsequently refined around observed target classes.

A separate investigated burst demonstrated why edge and origin must be examined together. In that incident, the retained aggregate contained 275 requests, of which 72 received an origin response. The origin returned 71 responses with status 404 and one status 200 for the public landing page. That investigation found no successful response for the examined sensitive-file probes. This incident is already part of the operational period and is not added again to the totals above.

A separate automated landing-page burst reached roughly 116 requests per minute. Its behavior justified closer examination and rate controls. Its volume and User-Agent rotation alone did not establish a botnet or a successful denial of service.

## Controls informed by this experience

- Enforce narrowly defined sensitive-target rules at both CDN and origin.
- Keep a versioned registry of protected targets and verify its preservation across deployment and rollback.
- Rate-limit repeated landing-page requests from one source while leaving unrelated API and asset routes outside that counter.
- Apply a separate origin-wide landing-page queue to contain aggregate bursts across many sources.
- Use a time-limited Managed Challenge during sustained distributed request pressure. Preserve verified-crawler exceptions at the edge.
- Require a confirmed behavioral series before automatically imposing a persistent source block. Distinguish expected authorization failures, missing resources, browser activity and authorized monitoring.
- Retain compact security summaries and explicitly report collection failures, sampling and gaps.

These are controls used or developed during the reported period. Their existence does not constitute a capacity benchmark or guarantee that every request is malicious or every attack will be stopped.

## Collection quality and limitations

- The historical archive through 12 November at 18:00 UTC contains **6,110 adjacent collection intervals** (6,070 five-minute intervals and 40 ten-minute catch-up intervals), with **no duplicate or overlapping intervals**, **no missing interval**, and **no archive-read error** in the extraction.
- **599 intervals** reported adaptive sampling above a sample interval of one. Counts are the provider-reported values. They have not been independently scaled or extrapolated.
- **Six intervals** hit either the summary-query or diagnostic-query result limit. Results in those intervals can omit groups or examples.
- The supplemental direct query covers six adjacent, non-overlapping UTC intervals from the archive cutoff through 18 November at 00:00 UTC. All six action intervals were sampled; none reached the action-group limit. The path results are bounded separately.
- The supplemental path filter covers seven target families. Other suspicious target types, overlong paths and unsupported decoded characters may be omitted; the register is not an exhaustive inventory of all probing.
- Collection continuity describes the retained records. It does not prove exhaustive Cloudflare telemetry or complete delivery of every underlying event.
- The diagnostic collection is capped at the provider query and further deduplicated and bounded per source, action and rule. Filtered path counts cannot be used as a percentage breakdown of all blocked requests.
- This dataset is security-event telemetry. It is not a full HTTP access log, a count of readers, or an estimate of unique visitors.
- Block, challenge, skip and HTTP status observations have different meanings. A response code alone does not prove access to sensitive content or successful compromise.
- The archive does not support a reliable count of distinct attacks. Traffic bursts, scanners and repeated requests are not automatically independent incidents.
- No performance-load test is implied. Availability and application security need separate checks.

## Privacy and reproducibility

This public export contains aggregate counts, a filtered scanner-target register with opaque identifiers replaced. It omits source addresses, network identifiers, provider rule identifiers, request identifiers, resource identifier values, User-Agent strings, query strings, cookies, request bodies, credentials and internal infrastructure details. The path register discloses selected technical probe paths and their aggregate sample counts; ordinary website routes are omitted.

The original extraction reads compressed records on the collector and emits aggregate counters and a sanitized scanner-target register. The update requests bounded Cloudflare aggregates and exports counts, filtered probe paths and sanitized aliases. It groups non-overlapping intervals, excludes Skip actions from threat totals and filters diagnostic paths to technical scanner targets. Raw evidence and the mapping of opaque placeholders remain access-controlled.

The totals are a fixed snapshot through the stated cutoff. Later events and later corrections require a new extraction and review.
