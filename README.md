# CS3700 Project 2 - BGP Router

This is the implementation of a simple BGP Router in rust.

## High Level Approach

The program starts by parsing command line arguments, spawning a thread for each socket it will connect to, then start the main thread in listening mode. Each of the child threads will read data from the unix sockets, and when detected a complete transmission will parse the packet to be sent back to the main thread. The main and child threads use `mpsc` channels to communicate with each other, an abstraction provided by rust for easy multi-thread tasks.

Back in the main thread, it receives incoming packets in the form of a parsed struct `BGPPacket`. It will then process the packet with a different subroutine depending on the message type. For update, revoke and data messages, it will additionally call `aggregate_routes()`, `revoke_routes()`, and `choose_route()` for better organization. The route table is passed back and forth between these functions and the main thread because of rust ownership troubles. 

After the main thread has updated its internal state and decided what to reply, it will send a message back to the child threads in the form of a string, where the thread will forward to its unix socket. This ensures that the main thread is rarely IO-blocked and can perform its operations while data is being received or sent.

The routing table is a simple vector/array of structs, which contains the necessary information for choosing the correct route during data message routing. Aggregation is performed be pair-wise comparison in O(n^2) speed, and will perform multiple iterations until no aggregation is detected anymore.

## Challenges faced

There were many major challenges. Rust's strict ownership rules means that many parts of the system needs to be carefully architectured to make sure that the correct part or correct thread of the program has ownership to the necessary variables. For example, we cannot just pass the unix socket listener to the child thread, then afterwards write to it in the main thread. 

The strong typing of rust also provided significant hurdles when parsing json. Although many of the variables like `localpref` are supposed to be a number, they are formatted in the json as a string, and any conversion between types has to be very explicit, and in some situations where this was overlooked much time was spent trying to debug the issue of why some variable comparisons are failing. Fortunately, the crate `serde_json` provided abstracted types which allowed us to deal with some level of uncertainty in the input structure, and the power of enums in rust allow the type `PacketMsg` to encapsulate the different possible msg types while still having the whole packet as statically-typed.

Moreover, since the protocal `UnixSeqpacket` used on the unix sockets is rarely used, both the official rust library and popular crates did not support it. A lot of time was spent searching around the internet, when finally I was lucky to find someone who has written a merge request proposing adding this feature to an official crate. Although his merge request was not accepted, I was able to directly pull from his developement branch to compile this project. Otherwise, this whole program would not be possible.

## Testing

The program has many debug statements added for easy debugging. Running the program with environment variable `RUST_LOG=debug` will display all the debug messages, providing a detailed step by step view of the program and eliminated any fear about concurrency of threads.

## External Libraries Used

clap - used for command line arguments parsing
ipnet - used for easier handling of IP address ranges and networks
unix_socket - used for establishing connection to the unix seqpacket sockets
serde_json - used for easier parsing of the json in both strongly-typed and weakly-typed modes
cute - used for easy list comprehension with Python-like syntax
env_logger - used for generating debug output
