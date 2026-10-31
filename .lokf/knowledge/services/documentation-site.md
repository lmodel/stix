---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/services/documentation-site
title: Documentation website
description: The knowledge website under `website/`, an Astro Starlight site built from the README, `docs/`, the schema's pages and the bundle, published at `https://lmodel.github.io/stix/` by `knowledge-website.yaml`, with redirects from the retired mkdocs addresses under `/elements/`.
genre: reference
resource: website/site.config.mjs
sources:
  - id: readme-website
    resource: website/README.md
    title: the site's description
  - id: site.config.mjs
    resource: website/site.config.mjs
    title: the DOCS and REDIRECTS settings
  - resource: website
    title: the site's sources and scripts
  - resource: docs
    title: the pages the site shows
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Documentation website

`website/` is an Astro Starlight site from the ktl-website templates. It has a page per concept with its trust label, a health page, a knowledge graph, the schema's pages, and the four files `lokf export` writes under `/knowledge/`.[^readme-website]

`website/site.config.mjs` sets the site at `https://lmodel.github.io/stix`. It keeps `templates-linkml` out of the docs pages, and redirects each page of the retired mkdocs site to its successor.[^site.config.mjs] An element that kept its name follows `/elements/<name>/` to `/schema/<name>/`. A renamed one goes to its successor, such as `/elements/Artifact/` to `/schema/StixArtifact/`, and the rest go to the schema's index. `/about` goes to `/docs/about/`.

[^readme-website]: website/README.md, the site's description
[^site.config.mjs]: website/site.config.mjs, the DOCS and REDIRECTS settings
