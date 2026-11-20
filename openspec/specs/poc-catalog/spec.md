# Spec — poc-catalog

Tests: `tests/test_poc_catalog.py`, `tests/validation/test_loop_c.py`
Datos: `harness/poc/catalog.yaml` · Código: `harness/poc/catalog.py`

## Requirement: Verificaciones inertes
Toda entrada del catálogo DEBE ser de tipo `inert_check`: confirma una debilidad observando la respuesta, sin ejecutar código en el objetivo ni extraer datos.

### Scenario: entrada de otro tipo
- GIVEN una entrada con `kind` distinto de `inert_check`
- WHEN se carga el catálogo
- THEN se rechaza

## Requirement: Solo laboratorio
Toda entrada DEBE ser `lab_only`.

### Scenario: entrada no marcada como laboratorio
- GIVEN una entrada con `lab_only: false`
- WHEN se carga el catálogo
- THEN se rechaza

<!-- Modificado por el change 006-sandbox-validation-loop-c -->
## Requirement: Aprobación registrada
Toda entrada DEBE tener `proposed_by`, `approved_by` y `approved_at`. `approved_by` NO DEBE ser igual a `proposed_by`: nadie aprueba su propia verificación.

### Scenario: entrada sin aprobación
- GIVEN una entrada sin `approved_at`
- WHEN se carga el catálogo
- THEN se rechaza

### Scenario: autoaprobación
- GIVEN una entrada con `approved_by` igual a `proposed_by`
- WHEN se carga el catálogo
- THEN se rechaza indicando la entrada

## Requirement: Parámetros declarados
La ejecución DEBE aceptar exactamente los parámetros declarados por la entrada, con valores de texto acotados y sin saltos de línea.

### Scenario: parámetro extra
- GIVEN un parámetro no declarado (por ejemplo `payload`)
- WHEN se ejecuta la verificación
- THEN se rechaza y no se envía nada

## Requirement: Aprobación humana previa
La ejecución NO DEBE enviar tráfico sin la aprobación del Reviewer para ese hallazgo.

### Scenario: sin aprobación
- GIVEN una verificación sin aprobación
- WHEN se intenta ejecutar
- THEN se rechaza y el sender no es invocado

## Requirement: Canario inerte
La verificación de reflexión DEBE usar un canario único sin marcado ejecutable y concluir solo observando la respuesta.

### Scenario: canario reflejado sin codificar
- GIVEN una respuesta que refleja el canario sin codificar
- WHEN se evalúa
- THEN el resultado es `validated`

### Scenario: canario codificado
- GIVEN una respuesta que codifica el canario
- WHEN se evalúa
- THEN el resultado es `not_validated`

<!-- Archivado desde el change 006-sandbox-validation-loop-c -->

## Requirement: Evaluador conocido
El `evaluator` de toda entrada DEBE existir en `EVALUATORS`. Un evaluador nuevo es código del harness y DEBE entrar por un change con revisión del `security-reviewer`.

### Scenario: evaluador inexistente
- GIVEN una entrada con `evaluator: run_shell`
- WHEN se carga el catálogo
- THEN se rechaza

## Requirement: Canario por intento
Cada intento de una verificación con canario DEBE usar un canario nuevo. Un canario de un intento anterior NO DEBE contar como positivo.

### Scenario: canario de una corrida anterior
- GIVEN una respuesta que refleja el canario del intento 1
- WHEN se evalúa el intento 2
- THEN el resultado no es positivo

## Requirement: Objetivos del laboratorio explícitos
Cada nombre de `lab_targets` DEBE estar en un mapa explícito a FQDN del laboratorio (`dvwa` → `dvwa.lab.test`, `juice-shop` → `juiceshop.lab.test`). Un host DEBE coincidir solo si su forma canónica completa (minúsculas, sin punto final, sin quitar caracteres) es uno de esos FQDN.

### Scenario: host parecido
- GIVEN los `lab_targets` `dvwa` y `juice-shop`
- WHEN se evalúan `dvwa.evil.example`, `d-v-w-a.lab.test`, `dvwa`, `xdvwa.lab.test` o `juice-shop.lab.test`
- THEN ninguno coincide, y sí coinciden `dvwa.lab.test`, `DVWA.lab.test.` y `juiceshop.lab.test`

### Scenario: objetivo desconocido en el catálogo
- GIVEN una entrada con `lab_targets: [dvwa, evil]`
- WHEN se carga el catálogo
- THEN se rechaza indicando `evil`
