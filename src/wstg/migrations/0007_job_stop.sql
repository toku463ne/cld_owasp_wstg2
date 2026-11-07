-- Stop one running item and let the job continue (the tester saw too much load).
-- Holds the seq of the item to stop; the worker kills that command only.
ALTER TABLE jobs ADD COLUMN stop_seq INTEGER;
