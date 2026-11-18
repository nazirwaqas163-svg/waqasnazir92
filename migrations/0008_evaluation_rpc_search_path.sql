-- Lock down the search path of the evaluation dataset versioning RPC.
ALTER FUNCTION public.create_evaluation_dataset_version(text, uuid, text, text, text, text, text, jsonb, text)
    SET search_path = pg_catalog, public, pg_temp;
