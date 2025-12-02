/* Procedure 2: Forkserver */
// Input: A target binary Adapter, a target binary Tracer, and probe locations PbLoc.
// Output: Null. 

// Start and wait for the startup signal of Generator.
Socket ← SetupAndWait()
while true do
    // Reboot the target (Adapter) and send the target's PID back to Generator.
    Pid ← ForkAndExec(Adapter)
    SendPID(Socket, Pid)
    // Wait for the Generator to feed the target with test cases and for the target to finish executing to get its status.
    Signal ← WaitStatus(Pid)
    // Send target's status back to Generator. 
    SendStatus(Socket, Signal)
    if Signal==SIGTRAP then          
        // Reboot the target (Tracer) again and send the target's PID to Generator.
        PidNew ← ForkAndExec(Tracer)
        SendPID(Socket, PidNew)
        // Wait for the Generator to feed the target with test cases and for the target to finish executing to get its status again.
        TracedCoverMap ← TraceCover(PidNew)
        SignalNew ← WaitStatus(PidNew)
        // Send the target's status and its traced coverage back to Generator.
        SendStatus(Socket, SignalNew)
        SendCover(Socket, TracedCoverMap)
        // Modify the target's probes to adjust interests.
        RecoveryModify(Adapter, PbLoc)
    end if
end while