--  The worker: its task body (one warmup iteration, the warmup
--  barrier, the main loop), one iteration, the session pump loop the
--  stream shape drives, and the round-trip comparison that decides
--  between a worker error and a data mismatch.

package Harness.Worker is

   function Shape_Name (Shape : Shape_Kind) return String;

   function Parse_Shape (Text : String; Shape : out Shape_Kind) return Boolean;

   --  Concurrency mode. This binding runs shared-handle: Ada tasks
   --  call into one Pipeline handle concurrently, which the shared
   --  library permits after construction, so --goroutines is the task
   --  count verbatim, never clamped. Each task is allocated with its
   --  worker id as a discriminant and reaches its own slot of the
   --  shared worker array through it.
   task type Runner (Id : Natural);

   type Runner_Access is access Runner;
   type Runner_Array is array (0 .. Max_Workers - 1) of Runner_Access;

end Harness.Worker;
