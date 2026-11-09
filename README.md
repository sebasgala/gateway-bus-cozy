# Gateway ESB (`gateway-bus-cozy`)

Punto de entrada único de la arquitectura Cozy. Gestiona el enrutamiento inteligente por prefijo hacia los microservicios de dominio, la verificación de credenciales JWT con RS256, respuestas estandarizadas en ProblemDetails (RFC 7807), agregación de salud de servicios en `/health` y propagación de trazas con `X-Correlation-ID`.

## Características
- **Enrutamiento por prefijo:** Direcciona `/api/v1/*`, `/api/v2/*` (Booking B2B) y `/graphql` hacia sus respectivos servicios.
- **Validación JWT RS256:** Verificación criptográfica con la clave pública emitida por el microservicio de usuarios.
- **Paso directo en Booking `/api/v2`:** Delegación de autenticación de negocio a los servicios dueños según §5.
- **Formato ProblemDetails:** Errores en `application/problem+json` con el campo `code`.
- **Salud agregada:** Endpoint `GET /health` que combina el estado de `usuarios`, `catalogo`, `disponibilidad`, `reservas` y `rabbitmq`.

## Instalación y compilación
```bash
npm ci
npm run build
```

## Pruebas
```bash
npm test
```

