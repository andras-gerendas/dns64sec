# dns64sec

DNS64 server with DNSSEC support.

## Compilation using G++

```
/usr/bin/g++ -Wall -Werror -Wextra -pedantic ./*.cc -lpthread -lssl -lcrypto -std=c++17 -I. -o ./dns64sec
```

## Command line parameters

The first position parameter can be used to set the location of the configuration file.

The default configuration file is located at: ```/etc/dns64sec.conf```

## Configuration options

### attempts

- Meaning: The number of attempts a resolver is tried in a request-response exchange before the next one is attempted (including the initial one).
- Default value: 3
- Type: A number between 1 and 10 inclusive

### enforce_dnssec

- Meaning: Whether the program should perform DNSSEC validation even if the client does not ask for it.
- Default value: false
- Type: boolean (true/false)

### ignore_resolvers_file

- Meaning: Whether the resolver file containing the name servers is not parsed, not taking the used resolvers from that file.
- Default value: false
- Type: boolean (true/false)

### listen_port

- Meaning: The port number used for listening to requests.
- Default value: 53
- Type: 16-bit unsigned integer

### logging_level

- Meaning: The severity level of the log messages sent to syslog. The values correspond to the syslog severity levels (e.g.: ```err``` equals ```LOG_ERR```), and a setting means that higher severity levels are logged as well.
- Default value: err
- Type: String out of the following values, with their syslog meaning in brackets: ```debug``` (```LOG_DEBUG```), ```info``` (```LOG_INFO```), ```warn``` (```LOG_WARNING```), ```err``` (```LOG_ERR```)

### prefix

- Meaning: The prefix used in the synthesised IPv6 addresses.
- Default value: 64:ff9b::/96
- Type: IPv6 network address

### receiver_count

- Meaning: The number of receiver threads the program uses. If the option and the ```receivers``` option are not set the number of threads is decided by a heuristic algorithm. The valid "```receivers```" option excludes the "```receiver_count```" option. Both the ```receiver_count``` and ```worker_count``` options need to be positive integers in order for the setting to be effective. The receivers are allocated first, then the workers, consecutively assigning processors to them. If the sum of the ```receiver_count``` and ```worker_count``` options is greater than the amount of processors available, the rest of the threads are allocated with a modulo of the amount of processors.
- Default value: None
- Type: 32-bit integer

### receivers

- Meaning: The list of processors where receiver threads should be located. If the option and the ```receiver_count``` option are not set, the number of threads is decided by a heuristic algorithm. The valid "```receivers```" option excludes the "```receiver_count```" option. Both the ```receivers``` and ```workers``` options need to be set in order for the setting to be effective, and if the same processor number appears in both lists, both receiver and worker threads are going to be bound to that processor.
- Default value: None
- Type: List of comma separated 16-bit unsigned integers or integer ranges. The use of a hyphen (-) indicates a range of processors, there can be multiple ranges.

### remove_dnssec_rrs

- Meaning: Whether the program should always remove DNSSEC RRs from the response.
- Default value: false
- Type: boolean (true/false)

### resolver_file

- Meaning: The name of the file used to get resolver information from, unless the configuration option ```ignore_resolvers_file``` is active.
- Default value: /etc/resolv.conf
- Type: A string with the absolute path of the filename.

### resolver_port

- Meaning: The port number used to send the requests to the resolver.
- Default value: 53
- Type: 16-bit unsigned integer

### resolvers

- Meaning: The list of resolvers used to forward the DNS requests to.
- Default value: None
- Type: A list of comma separated IPv4 or IPv6 addresses. The address list can be a mixture of the two address types. If the ```ignore_resolvers_file``` is not active these addresses are used alongside the addresses in the resolver file. Multiple occurences of this option are combined into one list, uniqueness is not checked.

### timeout

- Meaning: The time interval in milliseconds until a response is expected to arrive from a resolver.
- Default value: 5000
- Type: A number between 1000 and 60000 inclusive

### trusted_resolvers

- Meaning: The list of resolvers to which a secure connection is available, which means DNSSEC information coming from them can be trusted (and there is no need for further verification by the program).
- Default value: None
- Type: A list of comma separated IPv4 or IPv6 addresses. The address list can be a mixture of the two address types. The ```ignore_resolvers_file``` setting has no effect on this setting, as the resolvers can be non-direct resolvers. Multiple occurences of this option are combined into one list, uniqueness is not checked.

### udp_payload_size

- Meaning: The size of the buffer in bytes (effectively the maximum UDP payload size) used to send and receive DNS requests. Larger buffers than 512 bytes are achieved using the EDNS(0) extension. Beware of fragmentation if a large value is used. The value of the option must be at least 512.
- Default value: 512
- Type: 16-bit unsigned integer

### validate_dnssec

- Meaning: Whether the program should validate DNSSEC requests.
- Default value: false
- Type: boolean (true/false)

### worker_count

- Meaning: The number of worker threads the program uses. If the option and the ```workers``` option are not set the number of threads is decided by a heuristic algorithm. The valid "```workers```" option excludes the "```worker_count```" option. Both the ```receiver_count``` and ```worker_count``` options need to be positive integers in order for the setting to be effective. The receivers are allocated first, then the workers, consecutively assigning processors to them. If the sum of the ```receiver_count``` and ```worker_count``` options is greater than the amount of processors available, the rest of the threads are allocated with a modulo of the amount of processors.
- Default value: None
- Type: 32-bit integer

### workers

- Meaning: The list of processors where worker threads should be located. If the option and the ```worker_count``` option are not set, the number of threads is decided by a heuristic algorithm. The valid "```workers```" option excludes the "```worker_count```" option. Both the ```receivers``` and ```workers``` options need to be set in order for the setting to be effective, and if the same processor number appears in both lists, both receiver and worker threads are going to be bound to that processor.
- Default value: None
- Type: List of comma separated 16-bit unsigned integers or integer ranges. The use of a hyphen (-) indicates a range of processors, there can be multiple ranges.

## Syslog handling

The program writes into the configuration using the ```LOG_DAEMON``` facility.
