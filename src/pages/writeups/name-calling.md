---
layout: ../../layouts/WriteupLayout.astro
title: "Name Calling"
tag: "Forense"
tags:
  - Forense
  - BlueHens CTF
---
**Título:** Name Calling  
**Categoría:** Forense  
**Competencia:** BlueHens CTF  
**Descripción:** `I think someone called you chicken. You should do something about it`

## Reconocimiento

Para este reto nos entregan un unico archivo:

- `yousaidwhat.pcapng`

Por el tipo de archivo, la primera idea fue revisar que habia ocurrido en la red y buscar si en alguno de los intercambios habia una pista, un archivo util o directamente el flag.

Lo primero fue validar que realmente estuvieramos frente a una captura de red:

```bash
file yousaidwhat.pcapng
```

Salida relevante:

```text
pcapng capture file - version 1.0
```

Con eso claro, el siguiente paso fue hacer triage del trafico. En forense de red conviene responder primero estas preguntas:

1. Que hosts hablan entre si
2. Que protocolo parece mas interesante
3. Si hubo transferencia de archivos

## Analisis inicial del trafico

Al revisar conversaciones TCP, el patron que mas resaltaba era la comunicacion entre `172.16.248.1` y `172.16.248.147`, especialmente en el puerto `8000`:

```bash
tshark -r yousaidwhat.pcapng -q -z conv,tcp
```

Fragmento util:

```text
172.16.248.1:65255 <-> 172.16.248.147:8000
172.16.248.1:64889 <-> 172.16.248.147:8000
172.16.248.1:65102 <-> 172.16.248.147:8000
```

Eso apuntaba a un servidor HTTP o a un intercambio de recursos. Entonces el siguiente paso fue listar las peticiones HTTP en lugar de revisar paquetes uno por uno:

```bash
tshark -r yousaidwhat.pcapng -Y http.request \
  -T fields \
  -e frame.number -e ip.src -e ip.dst -e tcp.dstport -e http.request.uri
```

Y ahi aparecio lo importante:

```text
32   172.16.248.1  172.16.248.147  8000  /decoy2.txt
45   172.16.248.1  172.16.248.147  8000  /decoy1.txt
152  172.16.248.1  172.16.248.147  8000  /whoareyoucalling.zip
228  172.16.248.1  172.16.248.147  8000  /whossliming.jpg
279  172.16.248.1  172.16.248.147  8000  /stinky.jpeg
325  172.16.248.1  172.16.248.147  8000  /chicken.jpg
```

En ese punto ya se veia un patron claro. Habia varios archivos con nombres burlescos, algunos claramente senuelos (`decoy1`, `decoy2`) y otros mas llamativos, como `whoareyoucalling.zip` y `chicken.jpg`.

## Extraccion de objetos HTTP

En lugar de seguir todo desde Wireshark o desde los streams, lo mas practico fue extraer los objetos HTTP y analizarlos como archivos normales:

```bash
mkdir -p extracted/http
tshark -r yousaidwhat.pcapng --export-objects http,extracted/http
ls extracted/http
```

Entre lo exportado aparecieron:

- `whoareyoucalling.zip`
- `whossliming.jpg`
- `stinky.jpeg`
- `chicken.jpg`
- varios `decoy*.txt`

Los `decoy*.txt` no parecian prometedores, asi que se revisaron de forma rapida para confirmar si realmente eran ruido:

```bash
head -n 20 extracted/http/decoy1.txt
head -n 20 extracted/http/decoy2.txt
```

El contenido correspondia a respuestas de error y no aportaba nada util. Eso fue suficiente para descartarlos y concentrarse en los archivos relevantes.

## El ZIP protegido

El archivo que mas llamaba la atencion era `whoareyoucalling.zip`, porque su nombre sugeria directamente que podia contener la respuesta del reto.

Primero se reviso su contenido:

```bash
unzip -l extracted/http/whoareyoucalling.zip
```

Salida relevante:

```text
whoareyoucalling.txt
```

Eso era una buena senal: un ZIP pequeno con un `.txt` dentro suele ser un contenedor de flag o de una pista final. El problema fue que no se podia leer sin mas:

```bash
unzip -p extracted/http/whoareyoucalling.zip whoareyoucalling.txt
```

El ZIP pedia contrasena.

En este punto habia que decidir la siguiente hipotesis. Probar fuerza bruta no tenia mucho sentido: el reto ya daba suficiente contexto como para pensar que la password estaba escondida en algun otro artefacto de la misma captura.

## Busqueda de la contrasena

Como junto al ZIP habian descargado imagenes, una idea razonable era revisar metadata. En retos forenses es un lugar comun para esconder pistas y se puede comprobar rapido.

Se revisaron las imagenes con `exiftool`:

```bash
exiftool extracted/http/chicken.jpg
```

Y ahi aparecio la pista importante:

```text
Copyright : 6e6f626f64792063616c6c73206d6520636869636b656e21
```

Eso no parecia texto normal, pero si una cadena en hexadecimal. Decodificarla era el siguiente paso:

```bash
echo 6e6f626f64792063616c6c73206d6520636869636b656e21 | xxd -r -p
```

Resultado:

```text
nobody calls me chicken!
```

La frase encajaba con el nombre del reto y con el enunciado. No parecia una cadena aleatoria, sino una candidata muy clara a password del ZIP.

## Evidencia visual

La imagen que contenia la metadata sospechosa era esta:

![chicken](/writeups/assets/chicken.jpg)

La imagen por si sola no entrega la password, pero si refuerza el tema de "chicken", que coincide con el enunciado y con la frase escondida en la metadata.

## Extraccion final del flag

Con la frase decodificada, ya solo quedaba probarla:

```bash
unzip -P "nobody calls me chicken!" -p extracted/http/whoareyoucalling.zip whoareyoucalling.txt
```

Salida del comando:

```text
UDCTF{wh4ts_wr0ng_mcf1y}
```

## Flag

```text
UDCTF{wh4ts_wr0ng_mcf1y}
```
