export interface TeamSnapshot {
  name: string;
  year: number;
  globalRank: number;
  countryRank: number;
  ratingPoints: number;
}

export interface CompetitionResult {
  title: string;
  place: number;
  ctftimeUrl: string;
  finish?: string;
}

export interface ProfileSnapshot {
  alias: string;
  bio: string;
  joinDate: string;
}

export interface PortfolioData {
  team: TeamSnapshot;
  recentCompetitions: CompetitionResult[];
  neyi21: ProfileSnapshot;
}

const TEAM_ID = 408704;
const API_BASE = 'https://ctftime.org/api/v1';
const DEFAULT_TIMEOUT_MS = 4000;

const FALLBACK_DATA: PortfolioData = {
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
  neyi21: {
    alias: 'Neyi21',
    bio: 'Focused on solving forensics challenges.',
    joinDate: 'August 2025',
  },
};

async function fetchJson<T>(url: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
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

    if (!response.ok) {
      throw new Error(`CTFtime request failed (${response.status}): ${url}`);
    }

    return (await response.json()) as T;
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeNumber(value: unknown, fallback = 0): number {
  const numberValue = Number(value);
  return Number.isFinite(numberValue) ? numberValue : fallback;
}

function pickLatestRatingRecord(
  rating: TeamApiResponse['rating'],
  preferredYear: number
): { year: number; values: NonNullable<TeamApiResponse['rating']>[string] } | null {
  const source = rating ?? {};
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

  return candidates[0] ?? null;
}

type TeamApiResponse = {
  name?: string;
  primary_alias?: string;
  aliases?: string[];
  rating?: Record<
    string,
    {
      rating_place?: number | string;
      country_place?: number | string;
      rating_points?: number | string;
    }
  >;
};

type ResultsDataset = Record<
  string,
  {
    title?: string;
    scores?: Array<{ team_id?: number | string; team_name?: string; place?: number | string }>;
  }
>;

type EventMeta = {
  title?: string;
  finish?: string;
  ctftime_url?: string;
};

function normalizeTeamName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function getTeamScore(
  scores: Array<{ team_id?: number | string; team_name?: string; place?: number | string }>,
  teamId: number,
  aliases: Set<string>
) {
  const byId = scores.find((s) => Number(s?.team_id) === teamId);
  if (byId) return byId;

  return scores.find((s) => {
    const teamName = normalizeTeamName(String(s?.team_name ?? ''));
    return teamName.length > 0 && aliases.has(teamName);
  });
}

async function getRecentCompetitions(currentYear: number, teamAliases: string[]): Promise<CompetitionResult[]> {
  const [yearResultsRaw, prevResultsRaw] = await Promise.all([
    fetchJson<ResultsDataset>(`${API_BASE}/results/${currentYear}/`),
    fetchJson<ResultsDataset>(`${API_BASE}/results/${currentYear - 1}/`),
  ]);

  const aliases = new Set(teamAliases.map((name) => normalizeTeamName(name)).filter(Boolean));
  const candidates: Array<{ eventId: number; title: string; place: number }> = [];

  for (const dataset of [yearResultsRaw, prevResultsRaw]) {
    for (const [eventId, eventData] of Object.entries(dataset ?? {})) {
      const scores = Array.isArray(eventData?.scores) ? eventData.scores : [];
      const score = getTeamScore(scores, TEAM_ID, aliases);
      if (!score) continue;
      candidates.push({
        eventId: Number(eventId),
        title: eventData?.title || `CTF Event #${eventId}`,
        place: normalizeNumber(score.place, 9999),
      });
    }
  }

  candidates.sort((a, b) => a.place - b.place || b.eventId - a.eventId);
  const top = candidates.slice(0, 14);

  const metadata = await Promise.all(
    top.map(async (entry) => {
      try {
        const meta = await fetchJson<EventMeta>(`${API_BASE}/events/${entry.eventId}/`, 3500);
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

export async function getPortfolioData(): Promise<PortfolioData> {
  const currentYear = new Date().getUTCFullYear();

  try {
    const teamData = await fetchJson<TeamApiResponse>(`${API_BASE}/teams/${TEAM_ID}/`);
    const selectedRating = pickLatestRatingRecord(teamData?.rating, currentYear);
    const teamRating = selectedRating?.values ?? {};
    const aliases = [teamData?.name, teamData?.primary_alias, ...(teamData?.aliases ?? [])]
      .map((entry) => String(entry || '').trim())
      .filter(Boolean);

    const team: TeamSnapshot = {
      name: teamData?.name || FALLBACK_DATA.team.name,
      year: selectedRating?.year ?? currentYear,
      globalRank: normalizeNumber(teamRating?.rating_place, FALLBACK_DATA.team.globalRank),
      countryRank: normalizeNumber(teamRating?.country_place, FALLBACK_DATA.team.countryRank),
      ratingPoints: normalizeNumber(teamRating?.rating_points, FALLBACK_DATA.team.ratingPoints),
    };

    let recentCompetitions: CompetitionResult[] = FALLBACK_DATA.recentCompetitions;
    try {
      const liveCompetitions = await getRecentCompetitions(currentYear, aliases);
      if (liveCompetitions.length > 0) recentCompetitions = liveCompetitions;
    } catch {
      // keep fallback competitions
    }

    return {
      team,
      recentCompetitions,
      neyi21: FALLBACK_DATA.neyi21,
    };
  } catch {
    return FALLBACK_DATA;
  }
}
