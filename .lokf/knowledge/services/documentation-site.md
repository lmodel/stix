---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/services/documentation-site
title: Documentation website
description: The knowledge website under `website/`, a Hugo site built from the README, `docs/`, the schema's pages and the bundle, published at `https://lmodel.github.io/stix/` by `knowledge-website.yaml`, with redirects from the retired mkdocs addresses under `/elements/`.
genre: reference
resource: website/site.toml
sources:
  - id: readme-website
    resource: website/README.md
    title: the site's description
  - id: site.toml
    resource: website/site.toml
    title: the site's address, title and redirects
  - resource: website
    title: the site's sources and scripts
  - resource: docs
    title: the pages the site shows
generated:
  by: process:ktl-librarian
  at: "2026-11-15T02:49:31Z"
status: draft
---

# Documentation website

`website/` is a Hugo site from the ktl-website templates. It has a page per concept with its trust label, a health page, a knowledge graph, the schema's pages, and the four files `lokf export` writes under `/knowledge/`.[^readme-website]

`website/site.toml` sets the site at `https://lmodel.github.io/stix`. It keeps `templates-linkml` out of the docs pages, and redirects each page of the retired mkdocs site to its successor.[^site.toml] An element that kept its name follows `/elements/<name>/` to `/schema/<name>/`. A renamed one goes to its successor, such as `/elements/Artifact/` to `/schema/StixArtifact/`, and the rest go to the schema's index. `/about` goes to `/docs/about/`.

[^readme-website]: website/README.md, the site's description
[^site.toml]: website/site.toml, the site's address, title and redirects
