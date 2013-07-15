tail-comodo
===========

DESCRIPTION
-----------
This program offers a command line interface for viewing and monitoring the
firewall event log of the Comodo Internet Security Pro and [Comodo Firewall][3]
programs.

The user interface is heavily influenced by POSIX tail command implementations
in order to be already familiar with users.

USAGE
-----
    usage: tail-comodo [OPTION]
    
    Tails the Comodo Firewall event log
    
    Options:
      -a    Show all firewall events
      -f    Follow the log, displaying events as they occur
      -h    Display this help
      -N    Show the last N event, where N is positive number
      -s N  Sleep interval between log polling. Default is 1 second.
      -v    Verbose, print some internal info during execution
      -V    Show the version of the program
    
    Note: The environment variable TAIL_COMODO_FWDB overrides the default location
          for the database file to use.

OUTPUT
------
The output when tailing the event log consists of a number of records with
identical fields. Each line is a separate event record and has the following
fields:
`TIMESTAMP ACTION DIRECTION PROTOCOL SOURCE_IP SOURCE_PORT -> TARGET_IP TARGET_PORT PID PATH`

* *Timestamp*  Point in time where the event happened.
* *Action*     Action that Comodo took, which tend to be either to block the traffic or ask the user what to do.
* *Direction*  Either IN or OUT, the direction of the traffic.
* *Protocol*   The protocol used for the connection attempt.
* *Pid*        Process ID of the program that triggered the event
* *Path*       The executable file for the process ID.

Note that I probably haven't yet managed to map all actions and protocols to 
readable names, and anything I've missed will turn out as a question mark (?)
in the corresponding field.

If you run into a situation where you find a type that isn't mapped, let me
know and I'll add a proper translation for it.

Example output using `tail-comodo -1` for listing only the last event:

`2013-07-12 18:50:19 Blocked OUT IGMP  192.168.0.2 0  -> 224.0.0.252 0  5236 C:\app\Process Explorer\procexp64.exe`

COMPILING
---------
### Prerequisites ###
* C-Compiler, I recommend using [MinGW][1] and have tested it with gcc 4.7.2 
* GNU Make, I used version 3.80 from [Cygwin][2], but most any should do.
* SQLite3, will be downloaded automatically by the makefile if it isn't found, and put in the vendor directory.

For automatic downloading and unpacking of sqlite, you would also need the
following programs on the PATH.
* unzip       Any version should do, but I use 6.0 that came with cygwin.
* wget        Again, any should do, from cygwin I got version 1.13.4

With the pre-reqs in place, simply run make to build the program.

[1]: http://www.mingw.org/
[2]: http://www.cygwin.com/
[3]: http://www.comodo.com/home/internet-security/firewall.php
