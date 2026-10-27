# Category source audit

Reviewed: 2026-10-27. The catalog contains 27 precise openems categories backed by named UT1 source lists. Availability of a label does not prove that its data has been published or downloaded by an endpoint.

The primary source is the [Université Toulouse Capitole catalog](https://dsi.ut-capitole.fr/blacklists/). Its indexed catalog identifies `ai`, `bank`, `financial`, `jobsearch`, `webhosting`, and `celebrity` as separate lists. Each now maps to its own category; banks and financial services remain separate. These additions do not provide a broad General Business or Entertainment classifier.

The prior indexed snapshot listed 80 AI, 6,646 bank, 473 financial, 60,741 job-search, 45 web-hosting and 674 celebrity entries. These are historical source counts, not current openems coverage measurements. Direct catalog retrieval timed out during this review; a later catalog and license retrieval through the research tool returned HTTP 503. Live archive freshness and actual published counts must be verified from the deployment's category health and manifest.

Source legal references: [LICENSE.pdf](https://dsi.ut-capitole.fr/blacklists/download/LICENSE.pdf) and [CC BY-SA 4.0 text](https://dsi.ut-capitole.fr/blacklists/download/cc-by-sa-4-0.pdf). The previous indexed legal review identified CC BY-SA 4.0; direct live archive/license fetch remains pending. Published manifests retain source attribution. Redistribution must preserve attribution and applicable share-alike terms.

The importer accepts bounded lowercase list identifiers with underscores and hyphens, including the official `audio-video` and `residential-proxies` names. Traversal, links in place of domain files, duplicate files and oversized archives remain rejected. Archives without any supported list cannot replace the last publication.

Publication health distinguishes missing, empty, stale, current and invalid metadata. It includes source identity, taxonomy identity, publication time and age. Stale data remains available; an unavailable catalog is never represented as proof that a domain is unclassified. New action policies require their category data before activation, particularly allow exclusions under general monitoring.

Remaining gaps require a reviewed category provider or additional sourced lists, plus false-positive evaluation and update monitoring. Custom domain overrides provide immediate targeted exceptions, including an allow exception for Netflix within a blocked streaming category; service dependencies require acceptance testing. DNS observation measures queried domains and cannot establish every visited page or full URL.
