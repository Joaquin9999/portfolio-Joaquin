const TEAM_ID = 408704;
const API_BASE = 'https://ctftime.org/api/v1';
const DEFAULT_TIMEOUT_MS = 4500;

const FALLBACK = {
  team: {
    name: 'Ch0wn3rs',
    year: 2026,
    globalRank: 13,
    countryRank: 1,
    ratingPoints: 457.64,
  },
  recentCompetitions: [
    { title: 'BlueHens CTF 2026', place: 5, ctftimeUrl: 'https://ctftime.org/event/3235' },
    { title: "Batman's Kitchen CTF 2026", place: 10, ctftimeUrl: 'https://ctftime.org/event/3098' },
    { title: 'Nullcon Goa HackIM 2026 CTF', place: 12, ctftimeUrl: 'https://ctftime.org/event/3066' },
    { title: 'UTCTF 2026', place: 14, ctftimeUrl: 'https://ctftime.org/event/3133' },
    { title: 'tkbctf5', place: 17, ctftimeUrl: 'https://ctftime.org/event/3091' },
    { title: 'KalmarCTF 2026', place: 17, ctftimeUrl: 'https://ctftime.org/event/2983' },
    { title: 'TAMUctf 2026', place: 19, ctftimeUrl: 'https://ctftime.org/event/3095' },
    { title: 'Undutmaning 2026', place: 21, ctftimeUrl: 'https://ctftime.org/event/2987' },
  ],
};

function normalizeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeTeamName(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function pickLatestRatingRecord(rating, preferredYear) {
  const source = rating || {};
  const preferred = source[String(preferredYear)];
  if (preferred && Object.keys(preferred).length > 0) {
    return { year: preferredYear, values: preferred };
  }

  const candidates = Object.entries(source)
    .map(([year, values]) => ({ year: Number(year), values }))
    .filter(
      (item) =>
        Number.isFinite(item.year) &&
        item.values &&
        Object.keys(item.values).length > 0 &&
        (item.values.rating_place !== undefined ||
          item.values.country_place !== undefined ||
          item.values.rating_points !== undefined)
    )
    .sort((a, b) => b.year - a.year);

  return candidates[0] || null;
}

async function fetchJson(url, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent':
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        Referer: 'https://ctftime.org/',
      },
    });
    if (!response.ok) throw new Error(`CTFtime request failed (${response.status})`);
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function getTeamScore(scores, teamId, aliases) {
  const byId = scores.find((s) => Number(s?.team_id) === teamId);
  if (byId) return byId;

  return scores.find((s) => aliases.has(normalizeTeamName(s?.team_name)));
}

async function getRecentCompetitions(currentYear, aliases) {
  const [yearResultsRaw, prevResultsRaw] = await Promise.all([
    fetchJson(`${API_BASE}/results/${currentYear}/`),
    fetchJson(`${API_BASE}/results/${currentYear - 1}/`),
  ]);

  const candidates = [];
  for (const dataset of [yearResultsRaw, prevResultsRaw]) {
    for (const [eventId, eventData] of Object.entries(dataset || {})) {
      const scores = Array.isArray(eventData?.scores) ? eventData.scores : [];
      const score = getTeamScore(scores, TEAM_ID, aliases);
      if (!score) continue;
      candidates.push({
        eventId: Number(eventId),
        title: eventData?.title || `CTF Event #${eventId}`,
        place: normalizeNumber(score?.place, 9999),
      });
    }
  }

  candidates.sort((a, b) => a.place - b.place || b.eventId - a.eventId);
  const top = candidates.slice(0, 14);

  const metadata = await Promise.all(
    top.map(async (entry) => {
      try {
        const meta = await fetchJson(`${API_BASE}/events/${entry.eventId}/`, 3500);
        return {
          title: meta?.title || entry.title,
          place: entry.place,
          ctftimeUrl: meta?.ctftime_url || `https://ctftime.org/event/${entry.eventId}/`,
          finish: meta?.finish,
        };
      } catch {
        return {
          title: entry.title,
          place: entry.place,
          ctftimeUrl: `https://ctftime.org/event/${entry.eventId}/`,
          finish: undefined,
        };
      }
    })
  );

  metadata.sort((a, b) => a.place - b.place || String(b.finish || '').localeCompare(String(a.finish || '')));
  return metadata.slice(0, 8);
}

async function getPortfolioDataLive() {
  const currentYear = new Date().getUTCFullYear();
  try {
    const teamData = await fetchJson(`${API_BASE}/teams/${TEAM_ID}/`);
    const selectedRating = pickLatestRatingRecord(teamData?.rating, currentYear);
    const teamRating = selectedRating?.values || {};
    const aliases = new Set(
      [teamData?.name, teamData?.primary_alias, ...(teamData?.aliases || [])]
        .map((entry) => normalizeTeamName(entry))
        .filter(Boolean)
    );

    let recentCompetitions = FALLBACK.recentCompetitions;
    try {
      const liveCompetitions = await getRecentCompetitions(currentYear, aliases);
      if (liveCompetitions.length > 0) recentCompetitions = liveCompetitions;
    } catch {
      // Keep fallback competitions
    }

    return {
      team: {
        name: teamData?.name || FALLBACK.team.name,
        year: selectedRating?.year || currentYear,
        globalRank: normalizeNumber(teamRating?.rating_place, FALLBACK.team.globalRank),
        countryRank: normalizeNumber(teamRating?.country_place, FALLBACK.team.countryRank),
        ratingPoints: normalizeNumber(teamRating?.rating_points, FALLBACK.team.ratingPoints),
      },
      recentCompetitions,
    };
  } catch {
    return FALLBACK;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/ctftime') {
      const payload = await getPortfolioDataLive();
      return new Response(JSON.stringify(payload), {
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store, max-age=0',
        },
      });
    }

    return env.ASSETS.fetch(request);
  },
};
