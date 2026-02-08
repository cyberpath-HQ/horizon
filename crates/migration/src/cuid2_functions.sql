-- ============================================================================
-- CUID2 Implementation for PostgreSQL 18
-- Based on: https://github.com/paralleldrive/cuid2
-- Thread-safe, collision-resistant IDs with optional prefixes
-- ============================================================================

-- Base36 encoding function (0-9, a-z)
CREATE OR REPLACE FUNCTION base36_encode(num bigint) 
RETURNS text AS $$
DECLARE
    alphabet text := '0123456789abcdefghijklmnopqrstuvwxyz';
    base int := 36;
    result text := '';
    remainder int;
BEGIN
    IF num = 0 THEN
        RETURN '0';
    END IF;
    
    WHILE num > 0 LOOP
        remainder := num % base;
        result := substring(alphabet from (remainder + 1) for 1) || result;
        num := num / base;
    END LOOP;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE;

-- Convert hash bytes to base36 string
-- Matches the Rust implementation's hash conversion
CREATE OR REPLACE FUNCTION bytes_to_base36(hash_bytes bytea, target_length int)
RETURNS text AS $$
DECLARE
    result text;
    hash_bigint numeric;
BEGIN
    -- Convert bytea to big integer (treating as big-endian)
    hash_bigint := 0;
    FOR i IN 0..LEAST(length(hash_bytes) - 1, 31) LOOP
        hash_bigint := hash_bigint * 256 + get_byte(hash_bytes, i);
    END LOOP;
    
    -- Convert to base36 string
    IF hash_bigint = 0 THEN
        result := '0';
    ELSE
        result := '';
        WHILE hash_bigint > 0 AND length(result) < target_length LOOP
            result := substring('0123456789abcdefghijklmnopqrstuvwxyz' 
                from ((hash_bigint % 36)::int + 1) for 1) || result;
            hash_bigint := floor(hash_bigint / 36);
        END LOOP;
    END IF;
    
    -- Pad with zeros if needed and truncate to exact length
    result := lpad(result, target_length, '0');
    RETURN substring(result from 1 for target_length);
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE;

-- Generate random entropy string
-- Matches reference: Math.floor(random() * 36).toString(36)
CREATE OR REPLACE FUNCTION generate_entropy(entropy_length int DEFAULT 4)
RETURNS text AS $$
DECLARE
    alphabet text := '0123456789abcdefghijklmnopqrstuvwxyz';
    result text := '';
    random_val int;
BEGIN
    FOR i IN 1..entropy_length LOOP
        random_val := floor(random() * 36)::int;
        result := result || substring(alphabet from (random_val + 1) for 1);
    END LOOP;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE;

-- Generate system fingerprint
-- Combines: random entropy + PID + session info
-- Matches Rust: random numbers + process ID + thread ID
CREATE OR REPLACE FUNCTION generate_fingerprint()
RETURNS text AS $$
DECLARE
    fingerprint_input text;
    hash_bytes bytea;
BEGIN
    -- Combine multiple entropy sources like the reference implementation
    fingerprint_input := 
        -- Random entropy (simulates thread_rng().gen::<u128>())
        gen_random_bytes(32)::text ||
        -- Process/session identifier (simulates process ID)
        pg_backend_pid()::text ||
        -- Additional random entropy
        gen_random_bytes(16)::text ||
        -- Session/connection info (simulates thread ID)
        extract(epoch from clock_timestamp())::text ||
        -- Database identifier
        current_database();
    
    -- Hash with SHA3-512 and convert to base36 (32 chars)
    hash_bytes := digest(fingerprint_input, 'sha3-512');
    
    RETURN bytes_to_base36(hash_bytes, 32);
END;
$$ LANGUAGE plpgsql STABLE PARALLEL UNSAFE;

-- Main CUID2 generation function with prefix support
-- Usage: 
--   SELECT cuid2();                    -- Standard 24-char CUID2
--   SELECT cuid2(10);                  -- 10-char CUID2
--   SELECT cuid2(24, 'usr_');          -- With prefix: usr_abc123...
--   SELECT cuid2(32, 'txn_');          -- Max length with prefix
CREATE OR REPLACE FUNCTION cuid2(
    length int DEFAULT 24,
    prefix text DEFAULT ''
)
RETURNS text AS $$
DECLARE
    alphabet_letters text := 'abcdefghijklmnopqrstuvwxyz';
    first_char text;
    time_ms bigint;
    time_str text;
    counter_val bigint;
    counter_str text;
    entropy text;
    fingerprint text;
    combined_input text;
    hash_bytes bytea;
    hash_str text;
    result text;
    effective_length int;
BEGIN
    -- Validate prefix
    IF prefix IS NOT NULL AND prefix != '' THEN
        IF prefix !~ '^[a-z0-9_]+$' THEN
            RAISE EXCEPTION 'Prefix must contain only lowercase letters, numbers, and underscores';
        END IF;
    END IF;
    
    -- Calculate effective CUID length (excluding prefix)
    effective_length := length;
    
    -- Validate length (CUID2 spec: 2-32 characters)
    IF effective_length < 2 OR effective_length > 32 THEN
        RAISE EXCEPTION 'CUID2 length must be between 2 and 32 characters (excluding prefix)';
    END IF;
    
    -- 1. Generate first character (random letter a-z)
    -- Matches: STARTING_CHARS.choose(&mut thread_rng())
    first_char := substring(alphabet_letters from (floor(random() * 26)::int + 1) for 1);
    
    -- 2. Get timestamp in milliseconds (base36)
    -- Matches: SystemTime::now().duration_since(UNIX_EPOCH).as_millis()
    time_ms := (extract(epoch from clock_timestamp()) * 1000)::bigint;
    time_str := base36_encode(time_ms);
    
    -- 3. Get counter value (thread-safe sequence)
    -- Matches: COUNTER.with(|cell| cell.replace_with(...))
    -- Range: 0 to 476_782_367 (~22k hosts before 50% collision chance)
    counter_val := nextval('cuid2_counter_seq');
    counter_str := base36_encode(counter_val);
    
    -- 4. Generate random entropy
    -- Matches: create_entropy(self.length)
    entropy := generate_entropy(effective_length);
    
    -- 5. Get system fingerprint
    -- Matches: fingerprint() from thread-local
    fingerprint := generate_fingerprint();
    
    -- 6. Combine all inputs in order: time, entropy, count, fingerprint
    -- Matches exact order from Rust implementation
    combined_input := time_str || entropy || counter_str || fingerprint;
    
    -- 7. Hash with SHA3-512
    -- Matches: Sha3_512::new().update(...).finalize()
    hash_bytes := digest(combined_input::bytea, 'sha3-512');
    
    -- 8. Convert hash to base36 and truncate to (length - 1)
    -- Matches: BigUint::from_bytes_be(&hash).to_str_radix(36).truncate(length - 1)
    hash_str := bytes_to_base36(hash_bytes, effective_length - 1);
    
    -- 9. Combine first character with hash
    -- Matches: format!("{first_letter}{id_body}")
    result := first_char || hash_str;
    
    -- 10. Add prefix if provided
    IF prefix IS NOT NULL AND prefix != '' THEN
        result := prefix || result;
    END IF;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE;

-- Generate CUID2 slug (10 characters)
-- Matches: SLUG_CONSTRUCTOR.create_id()
CREATE OR REPLACE FUNCTION cuid2_slug(prefix text DEFAULT '')
RETURNS text AS $$
BEGIN
    RETURN cuid2(10, prefix);
END;
$$ LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE;

-- Validate CUID2 format
-- Matches: is_cuid2() from Rust implementation
CREATE OR REPLACE FUNCTION is_cuid2(
    input text, 
    expected_length int DEFAULT 24,
    expected_prefix text DEFAULT ''
)
RETURNS boolean AS $$
DECLARE
    cuid_part text;
    prefix_len int;
BEGIN
    IF input IS NULL THEN
        RETURN false;
    END IF;
    
    -- Handle prefix
    prefix_len := length(COALESCE(expected_prefix, ''));
    
    IF prefix_len > 0 THEN
        IF NOT starts_with(input, expected_prefix) THEN
            RETURN false;
        END IF;
        cuid_part := substring(input from (prefix_len + 1));
    ELSE
        cuid_part := input;
    END IF;
    
    -- Validate CUID part
    RETURN (
        length(cuid_part) = expected_length AND
        length(cuid_part) >= 2 AND
        length(cuid_part) <= 32 AND
        -- First char must be letter (a-z)
        substring(cuid_part from 1 for 1) ~ '^[a-z]$' AND
        -- Rest must be alphanumeric (0-9, a-z)
        substring(cuid_part from 2) ~ '^[0-9a-z]*$'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;

-- Create helper function for common prefixes
CREATE OR REPLACE FUNCTION cuid2_prefixed(
    prefix text,
    length int DEFAULT 24
)
RETURNS text AS $$
BEGIN
    RETURN cuid2(length, prefix);
END;
$$ LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE;

COMMENT ON FUNCTION cuid2(int, text) IS 
'Generate CUID2 collision-resistant ID with optional prefix. 
Based on: https://github.com/paralleldrive/cuid2
Thread-safe with ~4e+18 combinations at 24 chars.
Usage: cuid2(24, ''usr_'') or cuid2() for default.';

COMMENT ON FUNCTION cuid2_slug(text) IS 
'Generate short 10-character CUID2 slug with optional prefix.
Ideal for URL-friendly identifiers.';

COMMENT ON FUNCTION is_cuid2(text, int, text) IS 
'Validate if string matches CUID2 format with optional prefix check.';
