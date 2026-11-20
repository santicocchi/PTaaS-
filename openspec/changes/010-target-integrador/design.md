# Design — Change 010: `phantomcorp` en el laboratorio

## Contexto
```
 consola del curso (cyberlab_labnet) ──▶ phantomcorp   R2–R4 a mano (fuera del PTaaS)

 runner del PTaaS ──Harness.invoke──▶ red `lab` 10.99.0.0/24 (internal)
                                        ├─ dvwa.lab.test        (excluido en esta RoE)
                                        ├─ juiceshop.lab.test   (excluido en esta RoE)
                                        └─ phantomcorp.lab.test 10.99.0.12   ◀── nuevo
```

## Decisiones

### D1. Una segunda instancia del target dentro de la red aislada del PTaaS
**Elegido:** levantar otra instancia de `phantomcorp` en la red `lab` del PTaaS.
**Descartado:** conectar el runner a `cyberlab_labnet`. Esa red no es `internal`, no está en `lab_only_cidrs` y mezclaría el laboratorio del PTaaS con el del curso. El guard tendría que aceptar una subred que no controlamos.

Cada instancia es independiente: el PTaaS audita la suya y la consola del curso la suya. Las flags se entregan desde la del curso.

### D2. La imagen se construye desde el clon local, con perfil opcional
- Servicio `phantomcorp` con `profiles: [integrador]`: `docker compose up` sin el perfil no lo levanta, así el lab de siempre no cambia.
- `build.context: ${PTAAS_INTEGRADOR_CONTEXT:-./integrador-no-configurado}`, definido en `lab/.env` (ruta al directorio `entorno/phantomcorp` del clon del curso). No es `:?` porque compose interpola todos los servicios aunque su perfil esté apagado, y eso rompería el laboratorio de siempre; sin la variable, el build del perfil falla. `pull_policy: build`: la imagen nunca se busca en un registry. No se copia el target al repo: tiene licencia propia y sus flags no tienen que vivir acá. El Dockerfile del curso tiene internet durante el build (como cualquier `docker build`); el contenedor ya construido no.
- Solo red `lab` con `ipv4_address: 10.99.0.12`. Nunca en `tools`. El servicio solo admite las claves `profiles`, `build`, `image`, `pull_policy` y `networks` (allowlist en el test).
- Revisión de seguridad: la red `lab` reserva `ip_range: 10.99.0.128/25` para lo dinámico (runner, ZAP, sandbox) y los objetivos tienen IP fija fuera de ese rango (DVWA .10, Juice Shop .11, phantomcorp .12). Así un /32 de la RoE nunca apunta a otro contenedor y DVWA y Juice Shop se pueden excluir también por IP.
- Trazabilidad: el commit del repo del curso y el `Id` de la imagen `ptaas-phantomcorp` se anotan en la bitácora de la corrida (task 2.7; no hay digest de registry porque la imagen es local).

### D3. Alcance y catálogo
- `profiles.yaml`: `lab_only_domains` suma `phantomcorp.lab.test`. `lab_only_cidrs` no cambia.
- `LAB_TARGET_HOSTS["phantomcorp"] = {"phantomcorp.lab.test"}`.
- Catálogo `0.3.0`: las 6 entradas suman `phantomcorp` en `lab_targets` y suben a versión `1.1.0`. `proposed_by` = quien escribe el change; `approved_by` = Santi. Lo exige el requirement "Aprobación registrada".

### D4. RoE del integrador
`demo/roe-integrador.yaml`: `domains: [phantomcorp.lab.test]`, `cidrs: [10.99.0.12/32]`, exclusiones `dvwa.lab.test`, `juiceshop.lab.test` y sus IP fijas, fases `recon`, `correlate`, `analyze` y `validate` (las mismas que `roe-pipeline.yaml`). Refleja las reglas del engagement de la cátedra: solo ese host y nada destructivo.

### D5. `robots.txt` en el spider de ZAP
El recon tiene que ver lo que el sitio no linkea. Si el spider de ZAP 2.17.0 no lee `robots.txt` por defecto, se agrega `/JSON/spider/action/setOptionParseRobotsTxt/` a la lista de llamadas permitidas, con valor fijo `true`. Leer `robots.txt` es un GET más dentro del contexto: no envía formularios ni amplía el alcance.

## Riesgos
- **Ruta de build controlada por el usuario:** la imagen sale de un directorio local. Mitigación: corre en la red `internal`, sin socket de Docker ni volúmenes, igual que DVWA y Juice Shop.
- **IP fija ocupada:** resuelto con `ip_range` (ver D2).
- **GET a rutas de `robots.txt`:** el spider pide por GET lo que `robots.txt` declara. Una ruta que cambia estado por GET sería un riesgo; para este target se acepta (el contexto, `subtreeOnly` y el modo `protect` lo limitan al host). Excluir patrones destructivos del contexto queda para un change futuro.
- **DNS desde redes `internal`:** Docker anterior a la 26 reenvía consultas DNS externas desde una red `internal`. Usar Docker Desktop con Engine 26 o posterior.
