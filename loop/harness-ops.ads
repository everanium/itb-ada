--  The maintenance operations that mutate a live Pipeline handle
--  between iterations: master rotation (--rekey-every) and blob
--  reopen (--blob-cycle-every).

package Harness.Ops is

   --  Handle mutation. Runs the periodic Pipeline-mutating operations
   --  after a completed iteration: master rotation (--rekey-every)
   --  and blob reopen (--blob-cycle-every). Both intervals count
   --  per-worker iterations; the warmup iteration (iter 0) never
   --  triggers because the worker loop calls this for iter >= 1 only.
   --  Rekey rewrites the outer-layer keying of a live handle and a
   --  blob reopen replaces the handle outright; each takes the write
   --  lock, so in-flight cipher calls on other workers drain before
   --  anything changes and no encrypt is separated from its decrypt
   --  by either.
   function Maintenance
     (W : in out Worker_State; Iter : Count) return Boolean;

end Harness.Ops;
