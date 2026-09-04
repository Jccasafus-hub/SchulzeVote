CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- =========================================================
-- USERS
-- Pessoas cadastradas no SchulzeVote
-- =========================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,

    password_hash TEXT,

    status TEXT NOT NULL DEFAULT 'active',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- ELECTIONS
-- Eventos eleitorais
-- Uma eleição pode conter uma ou mais votações (contests)
-- =========================================================

CREATE TABLE elections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    title TEXT NOT NULL,
    description TEXT,

    status TEXT NOT NULL DEFAULT 'draft',

    starts_at TIMESTAMPTZ,
    ends_at TIMESTAMPTZ,

    timezone TEXT NOT NULL DEFAULT 'America/Sao_Paulo',

    created_by UUID REFERENCES users(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- CONTESTS
-- Cada votação existente dentro de uma eleição
-- Ex.: Presidente, Conselho Fiscal, uma deliberação etc.
-- =========================================================

CREATE TABLE contests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    election_id UUID NOT NULL
        REFERENCES elections(id)
        ON DELETE CASCADE,

    title TEXT NOT NULL,
    description TEXT,

    voting_method TEXT NOT NULL DEFAULT 'schulze',

    ballot_type TEXT NOT NULL DEFAULT 'ranking',

    secrecy_mode TEXT NOT NULL DEFAULT 'secret',

    display_vote_weight BOOLEAN NOT NULL DEFAULT FALSE,

    quorum_type TEXT NOT NULL DEFAULT 'none',

    quorum_value NUMERIC,

    quorum_basis TEXT NOT NULL DEFAULT 'voters',

    method_config JSONB NOT NULL DEFAULT '{}'::jsonb,

    position INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- OPTIONS
-- Candidatos ou outras alternativas disponíveis
-- dentro de uma votação
-- =========================================================

CREATE TABLE options (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    contest_id UUID NOT NULL
        REFERENCES contests(id)
        ON DELETE CASCADE,

    name TEXT NOT NULL,
    description TEXT,

    photo_url TEXT,

    position INTEGER NOT NULL DEFAULT 0,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- ELECTION_VOTERS
-- Liga um usuário previamente cadastrado a uma eleição
-- É aqui que fica, por exemplo, o peso daquele eleitor
-- naquela eleição
-- =========================================================

CREATE TABLE election_voters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    election_id UUID NOT NULL
        REFERENCES elections(id)
        ON DELETE CASCADE,

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    status TEXT NOT NULL DEFAULT 'authorized',

    vote_weight NUMERIC NOT NULL DEFAULT 1,

    authorized_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (election_id, user_id),

    CHECK (vote_weight > 0)
);


-- =========================================================
-- INDEXES
-- Aceleram consultas frequentes
-- =========================================================

CREATE INDEX idx_contests_election_id
    ON contests(election_id);

CREATE INDEX idx_options_contest_id
    ON options(contest_id);

CREATE INDEX idx_election_voters_election_id
    ON election_voters(election_id);

CREATE INDEX idx_election_voters_user_id
    ON election_voters(user_id);
