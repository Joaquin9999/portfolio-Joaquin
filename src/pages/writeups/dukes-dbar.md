---
layout: ../../layouts/WriteupLayout.astro
title: "Duke's DBAR Writeup"
description: "Analisis forense sobre abuso de Grafana SQL Expressions (CVE-2024-9264)."
tag: "Forensics"
date: "2026-03-18"
tags:
  - Forensics
  - Grafana
  - SQL Injection
  - Incident Response
---

## Resumen

Este writeup documenta un escenario de abuso en **Grafana SQL Expressions** relacionado con CVE-2024-9264.

## Objetivo

- Reconstruir la cadena de abuso.
- Identificar evidencia utilizable.
- Proponer mitigaciones tecnicas.

## Hallazgos Clave

1. Se observan consultas SQL encadenadas con expresiones no sanitizadas.
2. El flujo permite desviar resultados de paneles y manipular datos presentados.
3. La telemetria incompleta dificulta el analisis temporal si no hay logging adicional.

## Recomendaciones

- Aplicar parches oficiales de Grafana.
- Restringir permisos sobre datasources y paneles.
- Endurecer auditoria y alertas para consultas anomalias.
