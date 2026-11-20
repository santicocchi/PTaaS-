# Change 010 — Target del práctico integrador (`phantomcorp`) en el laboratorio

## Por qué
El práctico final del curso (`labs/labfinal-practico-integrador` de LabsSeguridadInformatica2026) pide auditar de caja negra el host `phantomcorp` y entregar un informe de pentest profesional. Se decidió un enfoque **híbrido**:

- El PTaaS aporta lo que ya sabe hacer bien: RoE y alcance verificable, recon (loop A), correlación y análisis (loop B), verificaciones **inertes** del catálogo (loop C), bitácora encadenada e informe con CWE y CVSS v4.
- Los hitos R2–R4 (foothold, post-explotación e impacto) se hacen **a mano** desde la consola del curso. El PTaaS no los automatiza: su catálogo es inerte por diseño (regla 4 de CLAUDE.md, `openspec/specs/poc-catalog`) y este change no lo cambia.

Hoy el PTaaS no puede tocar `phantomcorp`: el guard solo acepta `dvwa.lab.test` y `juiceshop.lab.test` dentro de `10.99.0.0/24`, y el target vive en otra red (`cyberlab_labnet`, sin `internal: true`).

## Qué cambia
1. `phantomcorp` se suma al laboratorio del PTaaS (`lab/docker-compose.yml`) como servicio **opcional** (perfil `integrador`), en la red `lab` (aislada) con IP fija `10.99.0.12` y alias `phantomcorp.lab.test`. La imagen se construye desde el clon local del repo del curso; no se copia el target a este repo.
2. `phantomcorp.lab.test` se agrega a `targets.lab_only_domains` y a `LAB_TARGET_HOSTS` (`phantomcorp`).
3. Las 6 entradas inertes del catálogo suman `phantomcorp` a `lab_targets` (nueva versión del catálogo, con aprobación humana registrada).
4. RoE nueva `demo/roe-integrador.yaml`: alcance solo `phantomcorp.lab.test` / `10.99.0.12/32`, DVWA y Juice Shop excluidos.
5. Verificar que el spider de ZAP lea `robots.txt` (hoy el adaptador no lo fija explícitamente).

## Fuera de alcance
- Explotación, extracción de datos o uso de credenciales robadas por parte del PTaaS.
- PoCs nuevas en el catálogo.
- Leer el código o las flags del target: la auditoría es de caja negra.
- Hallazgos manuales en el informe y exportación al template de la cátedra: change 011.

## Impacto
- Capabilities: `authorization` (alcance del laboratorio), `poc-catalog` (objetivos del catálogo).
- Sin cambios en el Scope Guard: solo en sus datos de configuración, que siguen pasando por los mismos tests.
