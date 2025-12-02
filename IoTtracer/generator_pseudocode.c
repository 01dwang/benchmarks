/* Procedure 1: Generator */
// Input: A initial seed queue InitSeeds.
// Output: Null. 

SeedsQueue ← InitSeeds
// Start and connect the specific port to send a signal to Forkserver. 
Socket ← SetupAndConnect()
while true do
    // Generate test cases and wait for Forkserver to return the target's PID.
    Testcase ← GenByMutate(SeedsQueue)
    WaitRemotePID(Socket)
    // Feed the test cases to the target.     
    SendToTarget(Testcase)
    // Wait for the Forkserver to return the target's status after running.
    Status ← WaitRemoteStatus(Socket) 
    if Status==SIGTRAP then
        // Wait for Forkserver to return the target's PID.
        WaitRemotePID(Socket)
        // Feed the same test cases to the target again.        
        SendToTarget(Testcase)
        // Wait for the Forkserver to return the target's status and its coverage.
        StatusNew ← WaitRemoteStatus(Socket)
        TracedCoverMap ← WaitRemoteCover(Socket)
        // Record the target's status and the reconstructed full coverage.
        SeedsQueue ← DoForSeeds(Testcase, StatusNew, TracedCoverMap)
    else
        // Record the target's status without special handling.
        SeedsQueue ← DoForSeeds(Testcase, Status, NULL)
    end if
end while