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
- `build.context: ${PTAAS_INTEGRADOR_CONTEXT:?...}`, definido en `lab/.env` (ruta al directorio `entorno/phantomcorp` del clon del curso). No se copia el target al repo: tiene licencia propia y sus flags no tienen que vivir acá.
- Solo red `lab` con `ipv4_address: 10.99.0.12`. Nunca en `tools`.
- Trazabilidad: el commit del repo del curso usado se anota en el MANIFEST de la corrida (no hay digest de registry porque la imagen es local).

### D3. Alcance y catálogo
- `profiles.yaml`: `lab_only_domains` suma `phantomcorp.lab.test`. `lab_only_cidrs` no cambia.
- `LAB_TARGET_HOSTS["phantomcorp"] = {"phantomcorp.lab.test"}`.
- Catálogo `0.3.0`: las 6 entradas suman `phantomcorp` en `lab_targets` y suben a versión `1.1.0`. `proposed_by` = quien escribe el change; `approved_by` = Santi. Lo exige el requirement "Aprobación registrada".

### D4. RoE del integrador
`demo/roe-integrador.yaml`: `domains: [phantomcorp.lab.test]`, `cidrs: [10.99.0.12/32]`, exclusiones `dvwa.lab.test` y `juiceshop.lab.test`, fases `recon`, `analyze` y `validate`. Refleja las reglas del engagement de la cátedra: solo ese host y nada destructivo.

### D5. `robots.txt` en el spider de ZAP
El recon tiene que ver lo que el sitio no linkea. Si el spider de ZAP 2.17.0 no lee `robots.txt` por defecto, se agrega `/JSON/spider/action/setOptionParseRobotsTxt/` a la lista de llamadas permitidas, con valor fijo `true`. Leer `robots.txt` es un GET más dentro del contexto: no envía formularios ni amplía el alcance.

## Riesgos
- **Ruta de build controlada por el usuario:** la imagen sale de un directorio local. Mitigación: corre en la red `internal`, sin socket de Docker ni volúmenes, igual que DVWA y Juice Shop.
- **IP fija ocupada:** si Docker ya asignó `10.99.0.12`, el compose falla al levantar. Mitigación: documentarlo y fijar también las IP de DVWA y Juice Shop si hace falta.
