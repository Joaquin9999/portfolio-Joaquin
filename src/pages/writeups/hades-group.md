---
layout: ../../layouts/WriteupLayout.astro
title: "Hades Group"
tag: "OSINT"
tags:
  - OSINT
  - UMDCTF
---
**Título:** Hades Group  
**Categoría:** OSINT  
**Competencia:** UMDCTF  
**Descripción:** `Case brief On February 3, 2026, a confidential tip reached your desk. "Hades Market", a pseudonymous prediction-market venue listing contracts on real-world outcomes involving journalists, streamers, and political activists, had been traced to a private Telegram channel operating as "Hades Group." The market was the front: traders took positions on whether specific individuals would be doxxed, swatted, or exposed by specific dates. The Telegram group was the back: a coordination room where the operator brokered the services that settled those contracts (doxxed profiles, coordinated swatting planning, brokered access to private records), so that their own book cleared in their favor. A source obtained a full export of the group's message history before being removed. The export covers roughly six weeks of activity across about 25 accounts, a mix of regular participants, one-time visitors, and apparent administrators. It is attached as hadesexport.json. You have been engaged as the independent OSINT investigator. Your objective Identify the group owner: the individual operating the service, the one clearing the spread on every contract Hades Market settled. The owner never posts under a personal account; all their messages appear as anonymous group posts (fromid beginning with "channel"). They are not perfectly silent, however. Flag Submit UMDCTF{REC-XXXXXXX}, where REC-XXXXXXX is the Document Record ID returned by the final document bot at the end of the owner's investigative chain. Investigative assets https://t.me/QuickOSINTSearch_XGBXL_389YBot: Underground leak database A. Query by username, UID, or phone number. https://t.me/EyeOfTheGod_ZF231_389YBot: Underground leak database B. Different source, different coverage. Query by username, UID, or phone number. https://t.me/SherlockTweaked_9VEZB_389YBot: Username intelligence. Returns username history and prior lookup activity. https://t.me/TGObserver_H6J3S_389YBot: Cached Telegram profile scrapes from a large parsing database. Returns phone numbers associated with a given username. https://t.me/StickerSleuth_VZBHY_389YBot: Sticker pack intelligence. Query by sticker set name. https://t.me/RussiaSearch_D4S38_389YBot: Russian document database. Returns identity records. Query by full name or phone number. https://t.me/ChinaSearch_44U32_389YBot: Chinese document database. Returns identity records. Query by full name or phone number. https://t.me/USDocs_6C582_389YBot : US document database. Returns identity records. Query by full name or phone number. https://t.me/CountrySearch_U6B8V_389YBot: Generic document database. Accepts full name and country name as arguments. Has partial overlap with the three regional bots but is the only source for certain records. Rules Do not flood the bots with automated requests. The bots only return data on seeded targets. Do not use them against real Telegram accounts or usernames outside the export. If a fictional handle in the export happens to collide with a real account, ignore the real account entirely. You are only permitted to use the provided JSON export and the bots listed above. No external scraping, no queries against live Telegram profiles, nothing beyond this kit. Do not share the flag, Record IDs, specific methodology, bot handles, or export data publicly while the CTF is running. Technical issues If a bot doesn't respond, returns something that looks broken, or you hit a problem with the export file itself, open a ticket in the UMDCTF Discord with the bot handle, the query you sent, and what you got back (or didn't). Fine print All personas, records, and identifiers in this challenge are fictional and generated for CTF use.`

## Reconocimiento

Este reto no iba de buscar en internet abierto, sino de seguir una cadena cerrada de pivotes dentro del material entregado y de los bots permitidos por el challenge.

Los elementos importantes eran dos:

1. El export del grupo de Telegram.
2. La lista de bots OSINT que el propio reto entregaba como parte del entorno.

La primera observacion importante era que el supuesto dueño nunca hablaba desde una cuenta personal, sino mediante publicaciones anonimas del grupo. Eso hacia pensar que el camino no iba a salir de un mensaje directo del operador, sino de algun detalle secundario: un archivo, un sticker, un alias viejo o un cruce de identidades.

## Punto de partida

El pivote mas importante aparecia en un mensaje donde el grupo enviaba un sticker personalizado.

Fragmento relevante del export:

```json
{
  "type": "message",
  "date": "2025-12-29T10:23:00Z",
  "from": "Hades Group",
  "from_id": "channel28740651",
  "media_type": "sticker",
  "sticker_set_name": "styx_reaction_pack",
  "file": "stickers/styx_reaction_pack_001.webp",
  "text": "",
  "id": 56
}
```

Ese dato era interesante porque en Telegram los packs de stickers pueden delatar al creador. En otras palabras, el sticker no resolvia el reto por si solo, pero si entregaba un identificador estable desde el cual empezar a pivotar.

## Paso 1: obtener el UID del creador

El primer paso fue consultar el nombre del pack en el bot de inteligencia de stickers:

- Herramienta: `@StickerSleuth_VZBHY_389YBot`
- Entrada: `styx_reaction_pack`

Salida relevante:

```text
Creator UID: 7816442093
```

![StickerSleuth](/writeups/assets/Screenshot_2026-04-27_at_8.34.16_PM.png)

Con eso ya no estabamos siguiendo al canal anonimo, sino a la cuenta que habia creado un recurso usado por ese canal.

## Paso 2: revisar alias y telefonos asociados

Con el UID en la mano, el siguiente paso fue consultar una base de datos mas amplia:

- Herramienta: `@EyeOfTheGod_ZF231_389YBot`
- Entrada: `7816442093`

La salida devolvia varios alias y varios telefonos asociados. El problema es que esos telefonos no parecian fiables para llegar a la identidad real; varios se veian como informacion desechable o poco util para atribucion.

![EyeOfTheGod](/writeups/assets/Screenshot_2026-04-27_at_8.36.35_PM.png)

En este punto la idea razonable no era insistir con los telefonos, sino usar los alias como pivot historico.

## Paso 3: buscar un alias antiguo

Se probaron los alias encontrados en el bot de historial de usuarios:

- Herramienta: `@SherlockTweaked_9VEZB_389YBot`
- Entrada: `@zeus_archive`

Salida relevante:

```text
Historical username: @thanatos_signal
```

![SherlockTweaked](/writeups/assets/Screenshot_2026-04-27_at_8.38.26_PM.png)

Ese era el primer salto realmente fuerte del reto. Los alias recientes estaban mas limpios, pero el alias historico abria la posibilidad de encontrar datos mas viejos y menos protegidos.

## Paso 4: obtener el numero real

Con el alias historico, el siguiente pivote fue consultar la cache de perfiles de Telegram:

- Herramienta: `@TGObserver_H6J3S_389YBot`
- Entrada: `@thanatos_signal`

Salida relevante:

```text
Phone: +49 160 5550 7318
```

![TGObserver](/writeups/assets/Screenshot_2026-04-27_at_8.38.45_PM.png)

Ese resultado ya tenia mucho mas valor. El prefijo `+49` apuntaba a Alemania y, a diferencia de los numeros anteriores, este aparecia como parte de un alias historico concreto.

## Paso 5: cruzar el telefono con un nombre

Con el telefono, se paso a una base de datos de filtraciones:

- Herramienta: `@QuickOSINTSearch_XGBXL_389YBot`
- Entrada: `+49 160 5550 7318`

Salida relevante:

```text
name: Niklas Hofmann
```

![QuickOSINTSearch](/writeups/assets/Screenshot_2026-04-27_at_8.39.02_PM.png)

En ese punto la cadena ya estaba bastante clara:

`sticker set -> UID -> alias -> alias historico -> telefono -> nombre real`

## Paso 6: recuperar el Record ID

Con el nombre legal y la jurisdiccion identificada, ya quedaba consultar el bot documental final:

- Herramienta: `@CountrySearch_U6B8V_389YBot`
- Entrada: `Niklas Hofmann`, `Germany`

Salida relevante:

```text
Record: REC-9305174
```

![CountrySearch 1](/writeups/assets/Screenshot_2026-04-27_at_8.39.16_PM.png)

![CountrySearch 2](/writeups/assets/Screenshot_2026-04-27_at_8.39.29_PM.png)

## Construccion de la flag

El reto pedia encapsular el Record ID dentro del formato de la competencia:

```text
UMDCTF{REC-9305174}
```

## Flag

```text
UMDCTF{REC-9305174}
```
