---
layout: ../../layouts/WriteupLayout.astro
title: "Hades Group"
tag: "OSINT"
tags:
  - OSINT
  - UMDCTF
---
**Title:** Hades Group  
**Category:** OSINT  
**Competition:** UMDCTF  
**Description:** `Case brief On February 3, 2026, a confidential tip reached your desk. "Hades Market", a pseudonymous prediction-market venue listing contracts on real-world outcomes involving journalists, streamers, and political activists, had been traced to a private Telegram channel operating as "Hades Group." The market was the front: traders took positions on whether specific individuals would be doxxed, swatted, or exposed by specific dates. The Telegram group was the back: a coordination room where the operator brokered the services that settled those contracts (doxxed profiles, coordinated swatting planning, brokered access to private records), so that their own book cleared in their favor. A source obtained a full export of the group's message history before being removed. The export covers roughly six weeks of activity across about 25 accounts, a mix of regular participants, one-time visitors, and apparent administrators. It is attached as hadesexport.json. You have been engaged as the independent OSINT investigator. Your objective Identify the group owner: the individual operating the service, the one clearing the spread on every contract Hades Market settled. The owner never posts under a personal account; all their messages appear as anonymous group posts (fromid beginning with "channel"). They are not perfectly silent, however. Flag Submit UMDCTF{REC-XXXXXXX}, where REC-XXXXXXX is the Document Record ID returned by the final document bot at the end of the owner's investigative chain. Investigative assets https://t.me/QuickOSINTSearch_XGBXL_389YBot: Underground leak database A. Query by username, UID, or phone number. https://t.me/EyeOfTheGod_ZF231_389YBot: Underground leak database B. Different source, different coverage. Query by username, UID, or phone number. https://t.me/SherlockTweaked_9VEZB_389YBot: Username intelligence. Returns username history and prior lookup activity. https://t.me/TGObserver_H6J3S_389YBot: Cached Telegram profile scrapes from a large parsing database. Returns phone numbers associated with a given username. https://t.me/StickerSleuth_VZBHY_389YBot: Sticker pack intelligence. Query by sticker set name. https://t.me/RussiaSearch_D4S38_389YBot: Russian document database. Returns identity records. Query by full name or phone number. https://t.me/ChinaSearch_44U32_389YBot: Chinese document database. Returns identity records. Query by full name or phone number. https://t.me/USDocs_6C582_389YBot : US document database. Returns identity records. Query by full name or phone number. https://t.me/CountrySearch_U6B8V_389YBot: Generic document database. Accepts full name and country name as arguments. Has partial overlap with the three regional bots but is the only source for certain records. Rules Do not flood the bots with automated requests. The bots only return data on seeded targets. Do not use them against real Telegram accounts or usernames outside the export. If a fictional handle in the export happens to collide with a real account, ignore the real account entirely. You are only permitted to use the provided JSON export and the bots listed above. No external scraping, no queries against live Telegram profiles, nothing beyond this kit. Do not share the flag, Record IDs, specific methodology, bot handles, or export data publicly while the CTF is running. Technical issues If a bot doesn't respond, returns something that looks broken, or you hit a problem with the export file itself, open a ticket in the UMDCTF Discord with the bot handle, the query you sent, and what you got back (or didn't). Fine print All personas, records, and identifiers in this challenge are fictional and generated for CTF use.`

## Recon

This challenge was not about open internet searching, but about following a closed chain of pivots using only the export and the bots explicitly provided by the challenge.

The two important pieces were:

1. The Telegram group export
2. The list of OSINT bots included as part of the challenge

The first important observation was that the owner never posted from a personal account. All owner messages appeared as anonymous group posts. That meant the solution probably would not come from a direct message by the operator, but from a secondary detail: a file, a sticker, an old alias, or some identity pivot.

## Starting Point

The key pivot appeared in a message where the group sent a custom sticker.

Relevant fragment from the export:

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

That mattered because in Telegram, sticker packs can expose the account that created them. The sticker itself did not solve the challenge, but it gave a stable identifier to start pivoting from.

## Step 1: Get the Creator UID

The first step was to query the sticker pack name in the sticker intelligence bot:

- Tool: `@StickerSleuth_VZBHY_389YBot`
- Input: `styx_reaction_pack`

Relevant output:

```text
Creator UID: 7816442093
```

![StickerSleuth](/writeups/assets/Screenshot_2026-04-27_at_8.34.16_PM.png)

At that point the investigation was no longer following the anonymous channel itself, but the account that had created a resource used by that channel.

## Step 2: Review Aliases and Phone Numbers

With the UID available, the next step was to query a broader database:

- Tool: `@EyeOfTheGod_ZF231_389YBot`
- Input: `7816442093`

The result returned several aliases and several phone numbers. The issue was that those phone numbers did not look trustworthy for attribution; some looked disposable or otherwise unhelpful.

![EyeOfTheGod](/writeups/assets/Screenshot_2026-04-27_at_8.36.35_PM.png)

At that point, the better move was not to insist on the phone numbers, but to use the aliases as a historical pivot.

## Step 3: Find an Older Alias

The aliases from the previous step were tested in the username history bot:

- Tool: `@SherlockTweaked_9VEZB_389YBot`
- Input: `@zeus_archive`

Relevant output:

```text
Historical username: @thanatos_signal
```

![SherlockTweaked](/writeups/assets/Screenshot_2026-04-27_at_8.38.26_PM.png)

This was the first major breakthrough. The recent aliases were cleaner, but the historical one opened the door to older and less protected data.

## Step 4: Get the Real Phone Number

With the historical alias in hand, the next pivot was the Telegram profile cache:

- Tool: `@TGObserver_H6J3S_389YBot`
- Input: `@thanatos_signal`

Relevant output:

```text
Phone: +49 160 5550 7318
```

![TGObserver](/writeups/assets/Screenshot_2026-04-27_at_8.38.45_PM.png)

That result was much more useful. The `+49` prefix pointed to Germany and, unlike the previous numbers, this one was tied to a specific historical alias.

## Step 5: Map the Phone Number to a Real Name

With the phone number, the next move was to query a leak database:

- Tool: `@QuickOSINTSearch_XGBXL_389YBot`
- Input: `+49 160 5550 7318`

Relevant output:

```text
name: Niklas Hofmann
```

![QuickOSINTSearch](/writeups/assets/Screenshot_2026-04-27_at_8.39.02_PM.png)

At that point the chain was already clear:

`sticker set -> UID -> alias -> historical alias -> phone number -> real name`

## Step 6: Recover the Record ID

Once the legal name and jurisdiction were identified, the final step was to query the document bot:

- Tool: `@CountrySearch_U6B8V_389YBot`
- Input: `Niklas Hofmann`, `Germany`

Relevant output:

```text
Record: REC-9305174
```

![CountrySearch 1](/writeups/assets/Screenshot_2026-04-27_at_8.39.16_PM.png)

![CountrySearch 2](/writeups/assets/Screenshot_2026-04-27_at_8.39.29_PM.png)

## Building the Flag

The challenge asked for the Record ID wrapped in the standard competition format:

```text
UMDCTF{REC-9305174}
```

## Flag

```text
UMDCTF{REC-9305174}
```
