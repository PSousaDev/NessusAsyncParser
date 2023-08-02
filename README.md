## [PT-BR]

### Biblioteca Feita para transformação de um ou multiplos arquivos com extensão .nessus

### Exemplo de uso de multiplos arquivos :

```js
await Promise.all(
  data.map(async (files) => {
    const parsedData = await NessusParser(fileBuffer, true);
  })
);
```

## [EN]

### Library Made for transforming one or multiple files with .nessus extension

### Example of using multiple files:

```js
await Promise.all(
  data.map(async (files) => {
    const parsedData = await NessusParser(fileBuffer, true);
  })
);
```
